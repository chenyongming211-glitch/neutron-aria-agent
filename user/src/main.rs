use clap::Parser;

mod api_client;
mod cli;
mod commands;

use self::cli::{
    ChainCommands, Cli, Commands, ConfigCommands, ConntrackCommands, DropsCommands,
    GroupCommands, MirrorCommands, PolicyCommands, QosCommands, SslCommands, SystemCommands,
    TcprtCommands, TraceCommands,
};

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

fn note_ssl_is_global(has_tap: bool) {
    if has_tap {
        eprintln!("Note: --tap is ignored for SSL observability commands; SSL data is host-global.");
    }
}

fn kernel_drop_query_from_cli(
    tap: Option<&String>,
    iface: Option<String>,
    top: Option<usize>,
    include_unattributed: bool,
) -> aria_api::KernelDropQuery {
    aria_api::KernelDropQuery {
        instance: tap.cloned(),
        iface,
        ifindex: None,
        reason: None,
        top,
        include_unattributed,
    }
}

fn print_kernel_drop_stats(entries: &[aria_api::KernelDropStatsEntry]) {
    println!(
        "{:<16} {:<16} {:<8} {:<20} {:<10} {:>12} {:>12} {}",
        "Instance", "Iface", "Ifindex", "Reason", "Proto", "Packets", "Bytes", "Source"
    );
    for entry in entries {
        println!(
            "{:<16} {:<16} {:<8} {:<20} {:<10} {:>12} {:>12} {}",
            entry.instance.as_deref().unwrap_or("-"),
            entry.iface.as_deref().unwrap_or("-"),
            entry.ifindex,
            entry.reason,
            entry.proto,
            entry.packets,
            entry.bytes,
            entry.source,
        );
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = api_client::ApiClient::new(&cli.api_url);
    let instance = get_instance(&cli);
    let has_tap = cli.tap.is_some();
    let tap_filter = cli.tap.clone();

    let result: Result<(), String> = match cli.command {
        Commands::System { action } => match action {
            SystemCommands::Start { iface, max_port_policies } => {
                if cli.tap.is_some() {
                    eprintln!("Error: 'system start' cannot be used with --tap. Use aria-agent to manage tap instances.");
                    std::process::exit(1);
                }
                match client.system_start(&aria_api::SystemStartRequest {
                    iface,
                    max_port_policies,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SystemCommands::Stop => {
                if cli.tap.is_some() {
                    eprintln!("Error: 'system stop' cannot be used with --tap. Use aria-agent to manage tap instances.");
                    std::process::exit(1);
                }
                match client.system_stop().await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Group { action } => match action {
            GroupCommands::Add { name, cidr } => {
                match client.add_group(&instance, &aria_api::AddGroupRequest { name, cidr }).await {
                    Ok(resp) => { println!("Added group '{}' with id {}", resp.name, resp.id); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            GroupCommands::Delete { name } => {
                match client.delete_group(&instance, &name).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            GroupCommands::List => {
                match client.list_groups(&instance).await {
                    Ok(resp) => {
                        if resp.groups.is_empty() {
                            println!("No groups configured");
                        } else {
                            println!("{:<10} {:<15} {}", "ID", "Name", "CIDRs");
                            for g in &resp.groups {
                                println!("{:<10} {:<15} {}", g.id, g.name, g.cidrs.join(", "));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            GroupCommands::WithStats => {
                match client.list_groups_with_stats(&instance).await {
                    Ok(resp) => {
                        if resp.groups.is_empty() {
                            println!("No groups configured");
                        } else {
                            println!("{:<10} {:<15} {:>15} {:>15} {:>15} {:>15} {}",
                                "ID", "Name", "InPkts", "InBytes", "OutPkts", "OutBytes", "CIDRs");
                            for g in &resp.groups {
                                println!("{:<10} {:<15} {:>15} {:>15} {:>15} {:>15} {}",
                                    g.id, g.name,
                                    g.ingress_packets, g.ingress_bytes,
                                    g.egress_packets, g.egress_bytes,
                                    g.cidrs.join(", "));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Policy { action } => match action {
            PolicyCommands::Add { src_group, dst_group, proto, action, ports, direction } => {
                match client.add_policy(&instance, &aria_api::AddPolicyRequest {
                    src_group: src_group.clone(),
                    dst_group: dst_group.clone(),
                    proto,
                    action,
                    direction: direction.clone(),
                    ports,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            PolicyCommands::Delete { src_group, dst_group, proto, direction } => {
                match client.delete_policy(&instance, &aria_api::DeletePolicyRequest {
                    src_group,
                    dst_group,
                    proto,
                    direction,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            PolicyCommands::Batch { file } => {
                let json_str = if file == "-" {
                    use std::io::Read;
                    let mut buf = String::new();
                    match std::io::stdin().read_to_string(&mut buf) {
                        Ok(_) => buf,
                        Err(e) => { eprintln!("Error: Failed to read stdin: {}", e); std::process::exit(1); },
                    }
                } else {
                    match std::fs::read_to_string(&file) {
                        Ok(s) => s,
                        Err(e) => { eprintln!("Error: Failed to read file '{}': {}", file, e); std::process::exit(1); },
                    }
                };

                let policies: Vec<aria_api::AddPolicyRequest> = match serde_json::from_str(&json_str) {
                    Ok(p) => p,
                    Err(e) => { eprintln!("Error: Invalid JSON: {}", e); std::process::exit(1); },
                };

                match client.batch_add_policies(&instance, &aria_api::BatchAddPoliciesRequest { policies }).await {
                    Ok(resp) => {
                        println!("Batch complete: {} added", resp.added);
                        if !resp.errors.is_empty() {
                            eprintln!("Errors:");
                            for err in &resp.errors {
                                eprintln!("  {}", err);
                            }
                            std::process::exit(1);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            PolicyCommands::List => {
                match client.list_policies(&instance).await {
                    Ok(resp) => {
                        if resp.policies.is_empty() {
                            println!("No policies configured");
                        } else {
                            println!("{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {}",
                                "SrcGroup", "DstGroup", "Proto", "Action", "Direction", "Bitmap", "Ports");
                            for p in &resp.policies {
                                let bitmap_str = match p.bitmap_idx {
                                    Some(idx) => idx.to_string(),
                                    None => "-".to_string(),
                                };
                                println!("{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {}",
                                    p.src_group, p.dst_group, p.proto, p.action,
                                    p.direction, bitmap_str,
                                    p.ports.as_deref().unwrap_or(""));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            PolicyCommands::WithStats => {
                match client.list_policies_with_stats(&instance).await {
                    Ok(resp) => {
                        if resp.policies.is_empty() {
                            println!("No policies configured");
                        } else {
                            println!("{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {:>12} {:>12} {:>12} {:>12} {}",
                                "SrcGroup", "DstGroup", "Proto", "Action", "Direction", "Bitmap",
                                "Packets", "Bytes", "DropPkts", "DropBytes", "Ports");
                            for p in &resp.policies {
                                let bitmap_str = match p.bitmap_idx {
                                    Some(idx) => idx.to_string(),
                                    None => "-".to_string(),
                                };
                                println!("{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {:>12} {:>12} {:>12} {:>12} {}",
                                    p.src_group, p.dst_group, p.proto, p.action,
                                    p.direction, bitmap_str,
                                    p.packets, p.bytes, p.dropped_packets, p.dropped_bytes,
                                    p.ports.as_deref().unwrap_or(""));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Stats { rules, flows, top, qos, groups, mirror, tcprt, drops } => {
            if !rules && !flows && !qos && !groups && !mirror && !tcprt && !drops {
                // Show overview
                match client.stats_overview(&instance).await {
                    Ok(stats) => {
                        println!("=== Firewall Statistics ===");
                        println!("  Groups:       {}", stats.groups);
                        println!("  Policies:     {}", stats.policies);
                        println!("  QoS rules:    {}", stats.qos_rules);
                        println!("  Mirror rules: {}", stats.mirror_rules);
                        println!("  Conntrack:    {} IPv4, {} IPv6", stats.conntrack_v4, stats.conntrack_v6);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                let mut has_error = false;
                if rules {
                    match client.stats_rules(&instance).await {
                        Ok(resp) => {
                            println!("=== Per-Rule Statistics ===");
                            if resp.rules.is_empty() {
                                println!("  No rule statistics collected yet");
                            } else {
                                println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<15} {:<15} {}",
                                    "SrcGroup", "DstGroup", "Proto", "Direction", "Packets", "Bytes", "DroppedPkts", "DroppedBytes");
                                for e in &resp.rules {
                                    println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<15} {:<15} {}",
                                        e.src_group, e.dst_group, e.proto, e.direction,
                                        e.packets, e.bytes, e.dropped_packets, e.dropped_bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading rule stats: {}", e); has_error = true; }
                    }
                }
                if qos {
                    match client.stats_qos(&instance).await {
                        Ok(resp) => {
                            println!("=== QoS Statistics ===");
                            if resp.rules.is_empty() {
                                println!("  No QoS statistics collected yet");
                            } else {
                                println!("{:<12} {:<10} {:<10} {:<12} {:<10} {:<12} {:<10} {}",
                                    "Group", "Direction", "PassPkts", "PassBytes", "DropPkts", "DropBytes", "ShapePkts", "ShapeBytes");
                                for e in &resp.rules {
                                    println!("{:<12} {:<10} {:<10} {:<12} {:<10} {:<12} {:<10} {}",
                                        e.group, e.direction,
                                        e.passed_packets, e.passed_bytes,
                                        e.dropped_packets, e.dropped_bytes,
                                        e.shaped_packets, e.shaped_bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading QoS stats: {}", e); has_error = true; }
                    }
                }
                if groups {
                    match client.stats_groups(&instance).await {
                        Ok(resp) => {
                            println!("=== Per-Group Statistics ===");
                            if resp.groups.is_empty() {
                                println!("  No group statistics collected yet");
                            } else {
                                println!("{:<15} {:<10} {:<15} {}",
                                    "Group", "Direction", "Packets", "Bytes");
                                for e in &resp.groups {
                                    println!("{:<15} {:<10} {:<15} {}",
                                        e.group, e.direction,
                                        e.packets, e.bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading group stats: {}", e); has_error = true; }
                    }
                }
                if mirror {
                    match client.stats_mirror(&instance).await {
                        Ok(resp) => {
                            println!("=== Mirror Statistics ===");
                            if resp.rules.is_empty() {
                                println!("  No mirror statistics collected yet");
                            } else {
                                println!("{:<12} {:<12} {:<8} {:<10} {:<8} {:<12} {:<12} {}",
                                    "SrcGroup", "DstGroup", "Proto", "Direction", "Global", "Mirrored", "Bytes", "Errors");
                                for e in &resp.rules {
                                    println!("{:<12} {:<12} {:<8} {:<10} {:<8} {:<12} {:<12} {}",
                                        e.src_group, e.dst_group, e.proto, e.direction,
                                        if e.is_global { "yes" } else { "no" },
                                        e.mirrored_packets, e.mirrored_bytes, e.errors);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading mirror stats: {}", e); has_error = true; }
                    }
                }
                if tcprt {
                    match client.list_tcprt(&instance, top).await {
                        Ok(resp) => {
                            println!("=== TCP-RT Statistics (top {}) ===", top);
                            if resp.flows.is_empty() {
                                println!("  No TCP-RT data collected yet");
                            } else {
                                println!("{:<20} {:<20} {:<8} {:<8} {:<12} {:<12} {:<12} {:<12} {:<8} {:<8} {:<8} {}",
                                    "Source", "Destination", "SPort", "DPort",
                                    "Handshake", "cRTT", "sRTT", "ART",
                                    "ReqRT", "RspRT", "Reqs", "State");
                                for e in &resp.flows {
                                    println!("{:<20} {:<20} {:<8} {:<8} {:<12.1} {:<12.1} {:<12.1} {:<12.1} {:<8} {:<8} {:<8} {}",
                                        e.src_ip, e.dst_ip, e.src_port, e.dst_port,
                                        e.handshake_us, e.rtt_client_us, e.rtt_server_us, e.art_us,
                                        e.retrans_req, e.retrans_resp, e.request_count, e.state);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading TCP-RT stats: {}", e); has_error = true; }
                    }
                }
                if drops {
                    let query = kernel_drop_query_from_cli(tap_filter.as_ref(), None, Some(top), false);
                    match client.list_kernel_drops(&query).await {
                        Ok(resp) => {
                            println!("=== Kernel Drop Statistics ===");
                            if resp.drops.is_empty() {
                                println!("  No kernel drops recorded");
                            } else {
                                print_kernel_drop_stats(&resp.drops);
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading kernel drop stats: {}", e); has_error = true; }
                    }
                }
                if flows {
                    match client.stats_flows(&instance, top).await {
                        Ok(resp) => {
                            println!("=== Top {} Flows ===", top);
                            if resp.flows.is_empty() {
                                println!("  No flow statistics collected yet");
                            } else {
                                println!("{:<40} {:<40} {:<8} {:<8} {:<8} {:<15} {}",
                                    "Source", "Destination", "SPort", "DPort", "Proto", "Packets", "Bytes");
                                for f in &resp.flows {
                                    println!("{:<40} {:<40} {:<8} {:<8} {:<8} {:<15} {}",
                                        f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto,
                                        f.packets, f.bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading flow stats: {}", e); has_error = true; }
                    }
                }
                if has_error { Err("Some stats queries failed".to_string()) } else { Ok(()) }
            }
        },
        Commands::Conntrack { action } => match action {
            ConntrackCommands::List => {
                match client.list_conntrack(&instance).await {
                    Ok(resp) => {
                        if resp.connections.is_empty() {
                            println!("No active connections");
                        } else {
                            println!("{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                                "Source", "Destination", "SPort", "DPort", "Proto", "State",
                                "Packets", "Bytes");
                            for c in &resp.connections {
                                println!("{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                                    c.src_ip, c.dst_ip, c.src_port, c.dst_port, c.proto,
                                    c.state, c.packets, c.bytes);
                            }
                            println!("\nTotal: {} connections", resp.total);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            ConntrackCommands::Flush => {
                match client.flush_conntrack(&instance).await {
                    Ok(resp) => { println!("Flushed {} connections", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Qos { action } => match action {
            QosCommands::Add { group, direction, rate, burst, priority, mode } => {
                match client.add_qos(&instance, &aria_api::AddQosRequest {
                    group,
                    direction,
                    rate,
                    burst,
                    priority,
                    mode,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            QosCommands::Delete { group, direction } => {
                match client.delete_qos(&instance, &aria_api::DeleteQosRequest {
                    group,
                    direction,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            QosCommands::List => {
                match client.list_qos(&instance).await {
                    Ok(resp) => {
                        if resp.rules.is_empty() {
                            println!("No QoS rules configured");
                        } else {
                            println!("{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {}",
                                "Group", "GroupID", "Direction", "Rate (B/s)", "Burst (B)", "Mode", "Priority");
                            for r in &resp.rules {
                                println!("{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {}",
                                    r.group, r.group_id, r.direction, r.rate_bps, r.burst_bytes, r.mode, r.priority);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            QosCommands::WithStats => {
                match client.list_qos_with_stats(&instance).await {
                    Ok(resp) => {
                        if resp.rules.is_empty() {
                            println!("No QoS rules configured");
                        } else {
                            println!("{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {}",
                                "Group", "GroupID", "Direction", "Rate (B/s)", "Burst (B)", "Mode",
                                "PassPkts", "PassBytes", "DropPkts", "DropBytes", "ShapePkts", "ShapeBytes", "Priority");
                            for r in &resp.rules {
                                println!("{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {}",
                                    r.group, r.group_id, r.direction, r.rate_bps, r.burst_bytes, r.mode,
                                    r.passed_packets, r.passed_bytes,
                                    r.dropped_packets, r.dropped_bytes,
                                    r.shaped_packets, r.shaped_bytes,
                                    r.priority);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Mirror { action } => match action {
            MirrorCommands::Add { direction, target, src_group, dst_group, proto } => {
                match client.add_mirror(&instance, &aria_api::AddMirrorRequest {
                    src_group,
                    dst_group,
                    proto,
                    direction,
                    target,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            MirrorCommands::Delete { direction, src_group, dst_group, proto } => {
                match client.delete_mirror(&instance, &aria_api::DeleteMirrorRequest {
                    src_group,
                    dst_group,
                    proto,
                    direction,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            MirrorCommands::List => {
                match client.list_mirror(&instance).await {
                    Ok(resp) => {
                        if resp.rules.is_empty() {
                            println!("No mirror rules configured");
                        } else {
                            println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {}",
                                "SrcGroup", "DstGroup", "Proto", "Direction", "Target", "IfIdx", "Global");
                            for r in &resp.rules {
                                println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {}",
                                    r.src_group, r.dst_group, r.proto, r.direction,
                                    r.target_iface, r.target_ifindex,
                                    if r.is_global { "yes" } else { "no" });
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            MirrorCommands::WithStats => {
                match client.list_mirror_with_stats(&instance).await {
                    Ok(resp) => {
                        if resp.rules.is_empty() {
                            println!("No mirror rules configured");
                        } else {
                            println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {:>12} {:>12} {}",
                                "SrcGroup", "DstGroup", "Proto", "Direction", "Target", "Global",
                                "MirrorPkts", "MirrorBytes", "Errors");
                            for r in &resp.rules {
                                println!("{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {:>12} {:>12} {}",
                                    r.src_group, r.dst_group, r.proto, r.direction,
                                    r.target_iface, if r.is_global { "yes" } else { "no" },
                                    r.mirrored_packets, r.mirrored_bytes,
                                    r.errors);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Tcprt { action } => match action {
            TcprtCommands::Top { by, top, watch, interval } => {
                commands::tcprt::handle_top(&client, &by, top, watch, interval).await
            }
            TcprtCommands::Flow { dst, dport, chain } => {
                commands::tcprt::handle_flow(&client, &dst, dport, chain.as_deref()).await
            }
            TcprtCommands::Histogram => {
                match client.tcprt_histogram(&instance).await {
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
                                let filled = if max_count > 0 { (b.count as usize * bar_width) / max_count as usize } else { 0 };
                                let bar: String = "\u{2588}".repeat(filled);
                                println!("  <= {:<8} {:>8} |{}", label, b.count, bar);
                            }
                            println!();
                            println!("  Total: {}  Sum: {:.1} us", resp.total, resp.sum_us);
                            println!("  p50: {:.1} us  p95: {:.1} us  p99: {:.1} us",
                                resp.p50_us, resp.p95_us, resp.p99_us);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            TcprtCommands::States => {
                match client.tcprt_states(&instance).await {
                    Ok(resp) => {
                        if resp.total_flows == 0 {
                            println!("No TCP-RT flows found");
                        } else {
                            println!("=== TCP State Distribution ({} flows) ===\n", resp.total_flows);
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
            TcprtCommands::Flush => {
                match client.flush_tcprt(&instance).await {
                    Ok(resp) => { println!("Flushed {} TCP-RT entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Chain { action } => match action {
            ChainCommands::Apply { file } => {
                let json_str = match std::fs::read_to_string(&file) {
                    Ok(s) => s,
                    Err(e) => { eprintln!("Error: Failed to read file '{}': {}", file, e); std::process::exit(1); },
                };
                let req: aria_api::CreateServiceChainRequest = match serde_json::from_str(&json_str) {
                    Ok(r) => r,
                    Err(e) => { eprintln!("Error: Invalid JSON: {}", e); std::process::exit(1); },
                };
                match client.create_chain(&req).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            ChainCommands::List => {
                match client.list_chains().await {
                    Ok(resp) => {
                        if resp.chains.is_empty() {
                            println!("No service chains configured");
                        } else {
                            println!("{:<20} {:<30} {}", "Name", "Description", "Hops");
                            for c in &resp.chains {
                                let hop_names: Vec<&str> = c.hops.iter().map(|h| h.name.as_str()).collect();
                                println!("{:<20} {:<30} {}", c.name, c.description, hop_names.join(" → "));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            ChainCommands::Show { name } => {
                match client.get_chain(&name).await {
                    Ok(chain) => {
                        println!("Chain: {}", chain.name);
                        if !chain.description.is_empty() {
                            println!("Description: {}", chain.description);
                        }
                        println!();
                        for (i, hop) in chain.hops.iter().enumerate() {
                            println!("  Hop #{}: {} ({})", i + 1, hop.name, hop.hop_type);
                            for tap in &hop.taps {
                                println!("    tap: {} ({})", tap.tap, tap.role);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            ChainCommands::Delete { name } => {
                match client.delete_chain(&name).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Drops { action } => match action {
            DropsCommands::List { iface, top, include_unattributed } => {
                let query = kernel_drop_query_from_cli(
                    tap_filter.as_ref(),
                    iface,
                    Some(top),
                    include_unattributed,
                );
                match client.list_kernel_drops(&query).await {
                    Ok(resp) => {
                        if resp.drops.is_empty() {
                            println!("No kernel drops recorded");
                        } else {
                            print_kernel_drop_stats(&resp.drops);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            DropsCommands::Flush { iface, include_unattributed, force } => {
                if !force {
                    Err("Refusing to flush kernel-drop statistics without --force".to_string())
                } else {
                    let query = kernel_drop_query_from_cli(
                        tap_filter.as_ref(),
                        iface,
                        None,
                        include_unattributed,
                    );
                    match client.flush_kernel_drops(&query).await {
                        Ok(resp) => { println!("Flushed {} kernel drop entries", resp.flushed); Ok(()) }
                        Err(e) => Err(e),
                    }
                }
            }
        },
        Commands::Trace { action } => match action {
            TraceCommands::Start { tap, src, dst, sport, dport, proto, wait, chain } => {
                commands::trace::handle_trace_start(
                    &client,
                    tap,
                    src,
                    dst,
                    sport,
                    dport,
                    proto,
                    wait,
                    chain,
                )
                .await
            }
        },
        Commands::Ssl { action } => match action {
            SslCommands::List { top } => {
                note_ssl_is_global(has_tap);
                match client.list_ssl(&instance, top).await {
                    Ok(resp) => {
                        if resp.connections.is_empty() {
                            println!("No SSL handshake records");
                        } else {
                            println!("{:<8} {:<8} {:<15} {:<64} {}",
                                "PID", "TID", "Handshake(us)", "SNI", "Seq");
                            for e in &resp.connections {
                                println!("{:<8} {:<8} {:<15.1} {:<64} {}",
                                    e.pid, e.tid, e.handshake_us, e.sni, e.seq);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Flush => {
                note_ssl_is_global(has_tap);
                match client.flush_ssl(&instance).await {
                    Ok(resp) => { println!("Flushed {} SSL handshake entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Http { top } => {
                note_ssl_is_global(has_tap);
                match client.list_ssl_http(&instance, top).await {
                    Ok(resp) => {
                        if resp.events.is_empty() {
                            println!("No SSL HTTP events");
                        } else {
                            println!("{:<8} {:<8} {:<8} {:<23} {:<30} {:<8} {}",
                                "PID", "TID", "Method", "Host", "Path", "Status", "Latency(us)");
                            for e in &resp.events {
                                println!("{:<8} {:<8} {:<8} {:<23} {:<30} {:<8} {:.1}",
                                    e.pid, e.tid, e.method, e.host, e.path, e.status_code, e.latency_us);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            SslCommands::HttpFlush => {
                note_ssl_is_global(has_tap);
                match client.flush_ssl_http(&instance).await {
                    Ok(resp) => { println!("Flushed {} SSL HTTP entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Enable => {
                note_ssl_is_global(has_tap);
                match client.update_ssl_config(true).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Disable => {
                note_ssl_is_global(has_tap);
                match client.update_ssl_config(false).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Status => {
                note_ssl_is_global(has_tap);
                match client.get_ssl_config().await {
                    Ok(cfg) => {
                        println!("Global SSL Observability: {}", if cfg.enabled { "ENABLED" } else { "DISABLED" });
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Errors { top } => {
                note_ssl_is_global(has_tap);
                match client.list_ssl_errors().await {
                    Ok(resp) => {
                        if resp.errors.is_empty() {
                            println!("No SSL errors");
                        } else {
                            let display: Vec<_> = resp.errors.into_iter().take(top).collect();
                            println!("{:<8} {:<8} {:<8} {:<18} {:<10} {:<12}", "PID", "TID", "SYSCALL", "TIMESTAMP", "RET", "HINT");
                            for e in &display {
                                println!("{:<8} {:<8} {:<8} {:<18} {:<10} {:<12}", e.pid, e.tid, e.syscall, e.timestamp, e.ret_code, e.error_hint);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            SslCommands::ErrorsFlush => {
                note_ssl_is_global(has_tap);
                match client.flush_ssl_errors().await {
                    Ok(resp) => { println!("Flushed {} SSL errors", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Config { action } => match action {
            ConfigCommands::Show => {
                match client.get_config(&instance).await {
                    Ok(cfg) => {
                        println!("=== Firewall Configuration ===");
                        println!("  conntrack:  {}", if cfg.conntrack { "on" } else { "off" });
                        println!("  monitoring: {}", if cfg.monitoring { "on" } else { "off" });
                        println!("  acl:        {}", if cfg.acl { "on" } else { "off" });
                        println!("  qos:        {}", if cfg.qos { "on" } else { "off" });
                        println!("  mirror:     {}", if cfg.mirror { "on" } else { "off" });
                        println!("  tcprt:      {}", if cfg.tcprt { "on" } else { "off" });
                        println!("  ssl:        {}", if cfg.ssl { "on" } else { "off" });
                        println!("  num_cpus:   {}", cfg.num_cpus);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            ConfigCommands::Set { key, value } => {
                let enabled = match value.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => {
                        eprintln!("Error: invalid value '{}': must be 'on' or 'off'", value);
                        std::process::exit(1);
                    }
                };

                if matches!(key.to_lowercase().as_str(), "ssl") {
                    note_ssl_is_global(has_tap);
                    match client.update_ssl_config(enabled).await {
                        Ok(_) => {
                            println!("Set ssl = {}", if enabled { "on" } else { "off" });
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    let req = match key.to_lowercase().as_str() {
                        "conntrack" | "ct" => aria_api::UpdateConfigRequest {
                            conntrack: Some(enabled),
                            monitoring: None,
                            acl: None,
                            qos: None,
                            mirror: None,
                            tcprt: None,
                            ssl: None,
                        },
                        "monitoring" | "mon" => aria_api::UpdateConfigRequest {
                            conntrack: None,
                            monitoring: Some(enabled),
                            acl: None,
                            qos: None,
                            mirror: None,
                            tcprt: None,
                            ssl: None,
                        },
                        "acl" | "policy" => aria_api::UpdateConfigRequest {
                            conntrack: None,
                            monitoring: None,
                            acl: Some(enabled),
                            qos: None,
                            mirror: None,
                            tcprt: None,
                            ssl: None,
                        },
                        "qos" => aria_api::UpdateConfigRequest {
                            conntrack: None,
                            monitoring: None,
                            acl: None,
                            qos: Some(enabled),
                            mirror: None,
                            tcprt: None,
                            ssl: None,
                        },
                        "mirror" => aria_api::UpdateConfigRequest {
                            conntrack: None,
                            monitoring: None,
                            acl: None,
                            qos: None,
                            mirror: Some(enabled),
                            tcprt: None,
                            ssl: None,
                        },
                        "tcprt" | "tcp-rt" => aria_api::UpdateConfigRequest {
                            conntrack: None,
                            monitoring: None,
                            acl: None,
                            qos: None,
                            mirror: None,
                            tcprt: Some(enabled),
                            ssl: None,
                        },
                        _ => {
                            eprintln!("Error: unknown config key '{}': must be 'conntrack', 'monitoring', 'acl', 'qos', 'mirror', 'tcprt', or 'ssl'", key);
                            std::process::exit(1);
                        }
                    };

                    match client.update_config(&instance, &req).await {
                        Ok(_) => {
                            println!("Set {} = {}", key, if enabled { "on" } else { "off" });
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        },
        Commands::Diagnose { dst, dport, chain } => {
            commands::diagnose::handle(&client, &instance, &dst, dport, chain.as_deref()).await
        },
        Commands::Instances => {
            match client.list_instances().await {
                Ok(resp) => {
                    if resp.instances.is_empty() {
                        println!("No instances registered");
                    } else {
                        println!("{:<20} {}", "Instance", "Status");
                        for inst in &resp.instances {
                            let status = if inst.active { "active" } else { "inactive" };
                            println!("{:<20} {}", inst.name, status);
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Health => {
            match client.health().await {
                Ok(resp) => {
                    println!("Status:    {}", resp.status);
                    println!("Version:   {}", resp.version);
                    println!("Instances: {}", resp.instances);
                    println!(
                        "KernelDrop: {}",
                        if resp.kernel_drop_available {
                            "available"
                        } else {
                            "unavailable"
                        }
                    );
                    if let Some(mode) = &resp.kernel_drop_mode {
                        println!("DropMode:  {}", mode);
                    }
                    println!(
                        "DropIfaces: {}",
                        resp.kernel_drop_managed_ifaces
                    );
                    if let Some(last_error) = &resp.kernel_drop_last_error {
                        println!("DropError: {}", last_error);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    };
}
