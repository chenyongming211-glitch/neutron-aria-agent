use clap::Parser;

mod api_client;
mod cli;
mod commands;

use self::cli::{Cli, Commands, TraceCommands};

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = api_client::ApiClient::new(&cli.api_url);
    let instance = get_instance(&cli);
    let has_tap = cli.tap.is_some();
    let tap_filter = cli.tap.clone();

    let result: Result<(), String> = match cli.command {
        Commands::System { action } => commands::system::handle_system_action(&client, has_tap, action).await,
        Commands::Group { action } => commands::group::handle_action(&client, &instance, action).await,
        Commands::Policy { action } => commands::policy::handle_action(&client, &instance, action).await,
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
                    let query = commands::drops::kernel_drop_query_from_cli(
                        tap_filter.as_ref(),
                        None,
                        Some(top),
                        false,
                    );
                    match client.list_kernel_drops(&query).await {
                        Ok(resp) => {
                            println!("=== Kernel Drop Statistics ===");
                            if resp.drops.is_empty() {
                                println!("  No kernel drops recorded");
                            } else {
                                commands::drops::print_kernel_drop_stats(&resp.drops);
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
        Commands::Conntrack { action } => commands::conntrack::handle_action(&client, &instance, action).await,
        Commands::Qos { action } => commands::qos::handle_action(&client, &instance, action).await,
        Commands::Mirror { action } => commands::mirror::handle_action(&client, &instance, action).await,
        Commands::Tcprt { action } => commands::tcprt::handle_action(&client, &instance, action).await,
        Commands::Chain { action } => commands::chain::handle_action(&client, action).await,
        Commands::Drops { action } => commands::drops::handle_action(&client, tap_filter.as_ref(), action).await,
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
        Commands::Ssl { action } => commands::ssl::handle_action(&client, &instance, has_tap, action).await,
        Commands::Config { action } => commands::config::handle_action(&client, &instance, has_tap, action).await,
        Commands::Diagnose { dst, dport, chain } => {
            commands::diagnose::handle(&client, &instance, &dst, dport, chain.as_deref()).await
        },
        Commands::Instances => commands::system::handle_instances(&client).await,
        Commands::Health => commands::system::handle_health(&client).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    };
}
