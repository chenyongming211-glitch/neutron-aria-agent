use clap::{Parser, Subcommand};

mod api_client;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";

#[derive(Parser)]
#[command(name = "ariactl")]
#[command(about = "eBPF/XDP Firewall Control Plane")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, env = "ARIA_API_URL", default_value = DEFAULT_API_URL, help = "aria-agent API URL")]
    api_url: String,
    #[arg(long, help = "Operate on a specific tap instance managed by aria-agent")]
    tap: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    System {
        #[command(subcommand)]
        action: SystemCommands,
    },
    Group {
        #[command(subcommand)]
        action: GroupCommands,
    },
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    Stats {
        #[arg(long, help = "Show per-rule packet/byte counts")]
        rules: bool,
        #[arg(long, help = "Show top-N flows by bytes")]
        flows: bool,
        #[arg(long, default_value = "20", help = "Number of top flows to show")]
        top: usize,
        #[arg(long, help = "Show QoS per-rule pass/drop/shaped counts")]
        qos: bool,
        #[arg(long, help = "Show per-group bandwidth statistics")]
        groups: bool,
        #[arg(long, help = "Show mirror statistics")]
        mirror: bool,
        #[arg(long, help = "Show TCP-RT (response time) statistics")]
        tcprt: bool,
        #[arg(long, help = "Show drop reason statistics")]
        drops: bool,
    },
    /// Connection tracking operations
    Conntrack {
        #[command(subcommand)]
        action: ConntrackCommands,
    },
    /// QoS rate limiting operations
    Qos {
        #[command(subcommand)]
        action: QosCommands,
    },
    /// Port mirror (SPAN) operations
    Mirror {
        #[command(subcommand)]
        action: MirrorCommands,
    },
    /// TCP response time monitoring
    Tcprt {
        #[command(subcommand)]
        action: TcprtCommands,
    },
    /// Drop reason profiler
    Drops {
        #[command(subcommand)]
        action: DropsCommands,
    },
    /// Packet trace for debugging
    Trace {
        #[command(subcommand)]
        action: TraceCommands,
    },
    /// Firewall configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// List all instances
    Instances,
    /// Check aria-agent health
    Health,
}

#[derive(Subcommand)]
enum SystemCommands {
    Start {
        #[arg(short, long)]
        iface: String,
        #[arg(long, default_value = "16384")]
        max_port_policies: u32,
    },
    Stop,
}

#[derive(Subcommand)]
enum GroupCommands {
    Add {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        cidr: String,
    },
    Delete {
        #[arg(short, long)]
        name: String,
    },
    List,
}

#[derive(Subcommand)]
enum PolicyCommands {
    Add {
        #[arg(short, long)]
        src_group: String,
        #[arg(short, long)]
        dst_group: String,
        #[arg(short, long)]
        proto: String,
        #[arg(short, long)]
        action: String,
        #[arg(short = 'o', long)]
        ports: Option<String>,
        #[arg(long, default_value = "ingress", help = "Direction: ingress or egress")]
        direction: String,
    },
    Delete {
        #[arg(short, long)]
        src_group: String,
        #[arg(short, long)]
        dst_group: String,
        #[arg(short, long)]
        proto: String,
        #[arg(long, default_value = "ingress", help = "Direction: ingress or egress")]
        direction: String,
    },
    /// Batch add policies from JSON file or stdin
    Batch {
        #[arg(short, long, help = "JSON file with policies array (use - for stdin)")]
        file: String,
    },
    List,
}

#[derive(Subcommand)]
enum ConntrackCommands {
    /// List active connections
    List,
    /// Flush all connections
    Flush,
}

#[derive(Subcommand)]
enum QosCommands {
    /// Add or update a QoS rate limit
    Add {
        #[arg(long, help = "Group name (or 'default' for global)")]
        group: String,
        #[arg(long, help = "Direction: ingress, egress, or both")]
        direction: String,
        #[arg(long, help = "Rate limit (e.g., 100mbps, 1gbps)")]
        rate: String,
        #[arg(long, default_value = "0", help = "Burst size (e.g., 1mb, 512kb). 0=auto")]
        burst: String,
        #[arg(long, default_value = "0", help = "Priority (0=highest, 7=lowest)")]
        priority: u8,
        #[arg(long, default_value = "policing", help = "Mode: policing (drop excess, works everywhere) or shaping (EDT delay, needs FQ qdisc)")]
        mode: String,
    },
    /// Delete a QoS rate limit
    Delete {
        #[arg(long)]
        group: String,
        #[arg(long, help = "Direction: ingress, egress, or both")]
        direction: String,
    },
    /// List all QoS rules
    List,
}

#[derive(Subcommand)]
enum MirrorCommands {
    /// Add a mirror rule
    Add {
        #[arg(long, help = "Direction: ingress, egress, or both")]
        direction: String,
        #[arg(long, help = "Target interface to mirror packets to")]
        target: String,
        #[arg(long, default_value = "any", help = "Source group (or 'any')")]
        src_group: String,
        #[arg(long, default_value = "any", help = "Destination group (or 'any')")]
        dst_group: String,
        #[arg(long, default_value = "any", help = "Protocol: tcp, udp, icmp, or any")]
        proto: String,
    },
    /// Delete a mirror rule
    Delete {
        #[arg(long, help = "Direction: ingress, egress, or both")]
        direction: String,
        #[arg(long, default_value = "any")]
        src_group: String,
        #[arg(long, default_value = "any")]
        dst_group: String,
        #[arg(long, default_value = "any")]
        proto: String,
    },
    /// List all mirror rules
    List,
}

#[derive(Subcommand)]
enum TcprtCommands {
    /// Cross-instance TopN summary sorted by a chosen metric
    Top {
        #[arg(long, default_value = "art", help = "Sort dimension: art, crtt, srtt, hs, retrans")]
        by: String,
        #[arg(long, default_value = "10", help = "Number of top flows to show")]
        top: usize,
        #[arg(long, help = "Enable dynamic refresh mode (like top)")]
        watch: bool,
        #[arg(long, default_value = "2", help = "Refresh interval in seconds (with --watch)")]
        interval: u64,
    },
    /// Cross-instance single flow detail with latency/loss breakdown
    Flow {
        #[arg(long, help = "Source IP")]
        src: String,
        #[arg(long, help = "Destination IP")]
        dst: String,
        #[arg(long, help = "Source port")]
        sport: u16,
        #[arg(long, help = "Destination port")]
        dport: u16,
    },
    /// Flush all TCP-RT tracking entries (requires --tap)
    Flush,
}

#[derive(Subcommand)]
enum DropsCommands {
    /// List drop reason statistics
    List,
    /// Flush all drop statistics
    Flush,
}

#[derive(Subcommand)]
enum TraceCommands {
    /// Start tracing packets matching a filter
    Start {
        #[arg(long, default_value = "", help = "Source IP to trace")]
        src: String,
        #[arg(long, default_value = "", help = "Destination IP to trace")]
        dst: String,
        #[arg(long, default_value = "0", help = "Source port to trace")]
        sport: u16,
        #[arg(long, default_value = "0", help = "Destination port to trace")]
        dport: u16,
        #[arg(long, default_value = "", help = "Protocol: tcp, udp, icmp, or any")]
        proto: String,
    },
    /// Show trace events
    Show {
        #[arg(long, default_value = "100", help = "Number of events to show")]
        top: usize,
    },
    /// Stop tracing (clear filter)
    Stop,
    /// Flush trace log
    Flush,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current firewall configuration
    Show,
    /// Set a configuration value
    Set {
        #[arg(help = "Configuration key: conntrack, monitoring, acl, or qos")]
        key: String,
        #[arg(help = "Value: on or off")]
        value: String,
    },
}

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

// ── TCP-RT Analyze helpers ──

/// 5-tuple flow key for cross-instance matching
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

/// Fetch TCP-RT data from all active instances, return (instance_name, flows_map) pairs.
async fn fetch_all_instance_flows(
    client: &api_client::ApiClient,
) -> Result<Vec<InstanceFlows>, String> {
    let instances_resp = client.list_instances().await?;
    let active: Vec<String> = instances_resp.instances.iter()
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
        all.push(InstanceFlows { name: inst_name.clone(), flows });
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
        _ /* art */ => entry.art_us,
    }
}

async fn run_tcprt_top(
    client: &api_client::ApiClient,
    by: &str,
    top: usize,
) -> Result<(), String> {
    let all_instances = fetch_all_instance_flows(client).await?;
    if all_instances.is_empty() {
        println!("No active instances found");
        return Ok(());
    }

    // Collect unique flow keys
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

    // Sort by max value of the chosen dimension across all instances (descending)
    unique_keys.sort_by(|a, b| {
        let val_a: f64 = all_instances.iter()
            .filter_map(|inst| inst.flows.get(a).map(|f| sort_value(f, by)))
            .fold(0.0f64, f64::max);
        let val_b: f64 = all_instances.iter()
            .filter_map(|inst| inst.flows.get(b).map(|f| sort_value(f, by)))
            .fold(0.0f64, f64::max);
        val_b.partial_cmp(&val_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    unique_keys.truncate(top);

    // Build flat rows: one row per (flow, instance), grouped by flow
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
    }

    let mut rows: Vec<Row> = Vec::new();
    for key in &unique_keys {
        // Collect points for this flow, sorted by sRTT descending (outermost first)
        let mut points: Vec<(&str, &aria_api::TcpRtEntry)> = all_instances.iter()
            .filter_map(|i| i.flows.get(key).map(|f| (i.name.as_str(), f)))
            .collect();
        points.sort_by(|a, b| b.1.rtt_server_us.partial_cmp(&a.1.rtt_server_us).unwrap_or(std::cmp::Ordering::Equal));

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
            });
        }
    }

    println!("{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10} {:<10} {:<10} {:<7} {:<7} {}",
        "Source", "Destination", "SPort", "DPort", "Instance",
        "ART (us)", "cRTT", "sRTT", "HS", "ReqRT", "RspRT", "State");
    for r in &rows {
        let art_str = if r.art == 0.0 { "-".to_string() } else { format!("{:.1}", r.art) };
        println!("{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10.1} {:<10.1} {:<10.1} {:<7} {:<7} {}",
            r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.instance,
            art_str, r.crtt, r.srtt, r.hs, r.req_rt, r.rsp_rt, r.state);
    }

    Ok(())
}

async fn run_tcprt_flow(
    client: &api_client::ApiClient,
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
) -> Result<(), String> {
    let req = aria_api::TcpRtBatchQueryRequest {
        tuples: vec![aria_api::TcpRtQueryTuple {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: sport,
            dst_port: dport,
        }],
    };
    let resp = client.batch_query_tcprt(&req).await?;
    if resp.results.is_empty() {
        println!("Flow {}:{} → {}:{} not found in any instance", src, sport, dst, dport);
        return Ok(());
    }

    // Collect observation points sorted by sRTT descending (outermost first)
    let mut points: Vec<(&str, &aria_api::TcpRtEntry)> = resp.results.iter()
        .map(|r| (r.instance.as_str(), &r.entry))
        .collect();
    points.sort_by(|a, b| b.1.rtt_server_us.partial_cmp(&a.1.rtt_server_us).unwrap_or(std::cmp::Ordering::Equal));

    println!("Flow: {}:{} → {}:{}\n", src, sport, dst, dport);

    // ── Cross-point metrics table ──
    let col_w = 12;
    print!("  {:<14}", "");
    for (name, _) in &points { print!(" {:>w$}", name, w = col_w); }
    println!();
    print!("  {:<14}", "──────────────");
    for _ in &points { print!(" {:>w$}", "────────────", w = col_w); }
    println!();

    let metrics: &[(&str, Box<dyn Fn(&aria_api::TcpRtEntry) -> String>)] = &[
        ("cRTT (us)", Box::new(|f: &aria_api::TcpRtEntry| format!("{:.1}", f.rtt_client_us))),
        ("sRTT (us)", Box::new(|f| format!("{:.1}", f.rtt_server_us))),
        ("ART (us)", Box::new(|f| if f.art_us == 0.0 { "-".to_string() } else { format!("{:.1}", f.art_us) })),
        ("HS (us)", Box::new(|f| format!("{:.1}", f.handshake_us))),
        ("ReqRT", Box::new(|f| format!("{}", f.retrans_req))),
        ("RspRT", Box::new(|f| format!("{}", f.retrans_resp))),
    ];
    for (label, extractor) in metrics {
        print!("  {:<14}", label);
        for (_, f) in &points { print!(" {:>w$}", extractor(f), w = col_w); }
        println!();
    }

    // ── Latency Breakdown ──
    if points.len() >= 2 {
        println!();
        print!("  {:<14}", "──────────────");
        for _ in &points { print!(" {:>w$}", "────────────", w = col_w); }
        println!();
        println!("  Breakdown      Component            Latency (us)");
        println!("  ─────────────  ───────────────────  ────────────");

        let n = points.len();
        struct Segment {
            label: String,
            value: f64,
        }
        let mut segments: Vec<Segment> = Vec::new();

        // External network: cRTT of outermost point
        let (_, outermost) = points[0];
        segments.push(Segment {
            label: "External Network".to_string(),
            value: outermost.rtt_client_us,
        });

        // Inter-point segments: sRTT difference between adjacent points
        if n == 2 {
            let (_, outer) = points[0];
            let (_, inner) = points[1];
            segments.push(Segment {
                label: "Host Overhead".to_string(),
                value: (outer.rtt_server_us - inner.rtt_server_us).max(0.0),
            });
        } else {
            // 3+ points: first gap = host overhead, middle gaps = security device, etc.
            for i in 0..n - 1 {
                let (_, outer) = points[i];
                let (_, inner) = points[i + 1];
                let diff = (outer.rtt_server_us - inner.rtt_server_us).max(0.0);
                let label = if i == 0 {
                    "Host Overhead".to_string()
                } else {
                    format!("Security DPI #{}", i)
                };
                segments.push(Segment { label, value: diff });
            }
        }

        // Innermost point → server: ART - sRTT of innermost
        let (_, innermost) = points[n - 1];
        let vm_processing = (innermost.art_us - innermost.rtt_server_us).max(0.0);
        segments.push(Segment {
            label: "App Processing".to_string(),
            value: vm_processing,
        });

        // Find bottleneck (max latency segment)
        let max_val = segments.iter().map(|s| s.value).fold(0.0f64, f64::max);

        for seg in &segments {
            let marker = if seg.value >= max_val && max_val > 0.0 { " ← bottleneck" } else { "" };
            println!("                 {:<21} {:.1}{}",
                seg.label, seg.value, marker);
        }

        // ── Packet Loss Breakdown ──
        println!();
        print!("  {:<14}", "──────────────");
        for _ in &points { print!(" {:>w$}", "────────────", w = col_w); }
        println!();
        println!("  Packet Loss    Location             Req Loss   Rsp Loss");
        println!("  ─────────────  ───────────────────  ─────────  ─────────");

        for i in 0..n - 1 {
            let (_, outer) = points[i];
            let (_, inner) = points[i + 1];
            let req_loss = (outer.retrans_req as i64 - inner.retrans_req as i64).max(0);
            let resp_loss = (outer.retrans_resp as i64 - inner.retrans_resp as i64).max(0);
            let label = if n == 2 {
                "Host".to_string()
            } else if i == 0 {
                "Host".to_string()
            } else {
                format!("Security #{}", i)
            };
            println!("                 {:<21} {:<10} {}",
                label, req_loss, resp_loss);
        }
        // Innermost → server
        let (_, innermost) = points[n - 1];
        println!("                 {:<21} {:<10} {}",
            "App Side", innermost.retrans_req, innermost.retrans_resp);
    }

    println!();
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = api_client::ApiClient::new(&cli.api_url);
    let instance = get_instance(&cli);

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
                                println!("{:<12} {:<12} {:<8} {:<10} {:<15} {}",
                                    "SrcGroup", "DstGroup", "Proto", "Direction", "Packets", "Bytes");
                                for e in &resp.rules {
                                    println!("{:<12} {:<12} {:<8} {:<10} {:<15} {}",
                                        e.src_group, e.dst_group, e.proto, e.direction,
                                        e.packets, e.bytes);
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
                    match client.list_drops(&instance).await {
                        Ok(resp) => {
                            println!("=== Drop Reason Statistics ===");
                            if resp.drops.is_empty() {
                                println!("  No drops recorded");
                            } else {
                                println!("{:<25} {:<10} {:<8} {:<12} {:<12} {:<12} {}",
                                    "Reason", "Direction", "Proto", "SrcGroup", "DstGroup", "Packets", "Bytes");
                                for e in &resp.drops {
                                    println!("{:<25} {:<10} {:<8} {:<12} {:<12} {:<12} {}",
                                        e.reason, e.direction, e.proto,
                                        e.src_group, e.dst_group,
                                        e.packets, e.bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => { eprintln!("Error reading drop stats: {}", e); has_error = true; }
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
        },
        Commands::Tcprt { action } => match action {
            TcprtCommands::Top { by, top, watch, interval } => {
                if watch {
                    loop {
                        print!("\x1B[2J\x1B[H");
                        if let Err(e) = run_tcprt_top(&client, &by, top).await {
                            eprintln!("Error: {}", e);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    }
                } else {
                    run_tcprt_top(&client, &by, top).await
                }
            }
            TcprtCommands::Flow { src, dst, sport, dport } => {
                run_tcprt_flow(&client, &src, &dst, sport, dport).await
            }
            TcprtCommands::Flush => {
                match client.flush_tcprt(&instance).await {
                    Ok(resp) => { println!("Flushed {} TCP-RT entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Drops { action } => match action {
            DropsCommands::List => {
                match client.list_drops(&instance).await {
                    Ok(resp) => {
                        if resp.drops.is_empty() {
                            println!("No drops recorded");
                        } else {
                            println!("{:<25} {:<10} {:<8} {:<12} {:<12} {:<12} {}",
                                "Reason", "Direction", "Proto", "SrcGroup", "DstGroup", "Packets", "Bytes");
                            for e in &resp.drops {
                                println!("{:<25} {:<10} {:<8} {:<12} {:<12} {:<12} {}",
                                    e.reason, e.direction, e.proto,
                                    e.src_group, e.dst_group,
                                    e.packets, e.bytes);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            DropsCommands::Flush => {
                match client.flush_drops(&instance).await {
                    Ok(resp) => { println!("Flushed {} drop entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Trace { action } => match action {
            TraceCommands::Start { src, dst, sport, dport, proto } => {
                match client.start_trace(&instance, &aria_api::TraceStartRequest {
                    src_ip: src,
                    dst_ip: dst,
                    src_port: sport,
                    dst_port: dport,
                    proto,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            TraceCommands::Show { top } => {
                match client.list_trace(&instance, top).await {
                    Ok(resp) => {
                        if resp.events.is_empty() {
                            println!("No trace events captured");
                        } else {
                            println!("{:<6} {:<12} {:<16} {:<16} {:<6} {:<6} {:<12} {:<8} {:<10} {:<14} {:<14} {}",
                                "Seq", "Hook", "Source", "Destination", "SPort", "DPort",
                                "Result", "Dir", "CT State", "SrcGroup", "DstGroup", "Drop Reason");
                            for e in &resp.events {
                                println!("{:<6} {:<12} {:<16} {:<16} {:<6} {:<6} {:<12} {:<8} {:<10} {:<14} {:<14} {}",
                                    e.seq, e.hook, e.src_ip, e.dst_ip, e.src_port, e.dst_port,
                                    e.result, e.direction, e.ct_state,
                                    e.src_group, e.dst_group, e.drop_reason);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            TraceCommands::Stop => {
                match client.stop_trace(&instance).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            TraceCommands::Flush => {
                match client.flush_trace(&instance).await {
                    Ok(resp) => { println!("Flushed {} trace events", resp.flushed); Ok(()) }
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

                let req = match key.to_lowercase().as_str() {
                    "conntrack" | "ct" => aria_api::UpdateConfigRequest {
                        conntrack: Some(enabled),
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: None,
                    },
                    "monitoring" | "mon" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: Some(enabled),
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: None,
                    },
                    "acl" | "policy" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: Some(enabled),
                        qos: None,
                        mirror: None,
                        tcprt: None,
                    },
                    "qos" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: Some(enabled),
                        mirror: None,
                        tcprt: None,
                    },
                    "mirror" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: Some(enabled),
                        tcprt: None,
                    },
                    "tcprt" | "tcp-rt" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: Some(enabled),
                    },
                    _ => {
                        eprintln!("Error: unknown config key '{}': must be 'conntrack', 'monitoring', 'acl', 'qos', 'mirror', or 'tcprt'", key);
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
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
