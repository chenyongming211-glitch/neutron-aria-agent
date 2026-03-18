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
    /// List TCP-RT flows sorted by application response time
    List {
        #[arg(long, default_value = "20", help = "Number of top flows to show")]
        top: usize,
    },
    /// Flush all TCP-RT tracking entries
    Flush,
    /// Cross-observation-point analysis with latency breakdown and packet loss
    Analyze {
        #[arg(long, default_value = "10", help = "Number of top flows to show")]
        top: usize,
        #[arg(long, help = "Filter by group name for detailed per-flow cross-point analysis")]
        group: Option<String>,
        #[arg(long, help = "Enable dynamic refresh mode (like top)")]
        watch: bool,
        #[arg(long, default_value = "2", help = "Refresh interval in seconds (with --watch)")]
        interval: u64,
    },
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

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let prefix_len: u32 = match parts[1].parse() { Ok(v) => v, Err(_) => return false };

    // IPv4
    if let (Ok(ip_addr), Ok(net_addr)) = (ip.parse::<std::net::Ipv4Addr>(), parts[0].parse::<std::net::Ipv4Addr>()) {
        if prefix_len > 32 { return false; }
        if prefix_len == 0 { return true; }
        let mask = !0u32 << (32 - prefix_len);
        return (u32::from(ip_addr) & mask) == (u32::from(net_addr) & mask);
    }
    // IPv6
    if let (Ok(ip_addr), Ok(net_addr)) = (ip.parse::<std::net::Ipv6Addr>(), parts[0].parse::<std::net::Ipv6Addr>()) {
        if prefix_len > 128 { return false; }
        if prefix_len == 0 { return true; }
        let ip_bits = u128::from(ip_addr);
        let net_bits = u128::from(net_addr);
        let mask = !0u128 << (128 - prefix_len);
        return (ip_bits & mask) == (net_bits & mask);
    }
    false
}

fn find_group(ip: &str, groups: &[aria_api::GroupEntry]) -> String {
    for g in groups {
        for cidr in &g.cidrs {
            if ip_in_cidr(ip, cidr) {
                return g.name.clone();
            }
        }
    }
    "unknown".to_string()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn run_analyze(
    client: &api_client::ApiClient,
    current_instance: &str,
    top: usize,
    group_filter: Option<&str>,
) -> Result<(), String> {
    // 1. Discover all active instances
    let instances_resp = client.list_instances().await?;
    let active: Vec<String> = instances_resp.instances.iter()
        .filter(|i| i.active)
        .map(|i| i.name.clone())
        .collect();

    if active.is_empty() {
        println!("No active instances found");
        return Ok(());
    }

    // 2. Pull groups from current instance (for IP→group mapping)
    let groups = client.list_groups(current_instance).await
        .map(|r| r.groups)
        .unwrap_or_default();

    // 3. Pull tcprt data from all instances
    let mut all_instances: Vec<InstanceFlows> = Vec::new();
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
        all_instances.push(InstanceFlows { name: inst_name.clone(), flows });
    }

    let now = {
        use std::time::SystemTime;
        let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
        let secs = d.as_secs();
        let h = (secs / 3600) % 24;
        let m = (secs / 60) % 60;
        let s = secs % 60;
        format!("{:02}:{:02}:{:02}", h, m, s)
    };

    if let Some(grp) = group_filter {
        // ── Detailed per-flow cross-point analysis for a specific group ──
        println!("=== TCP-RT Analysis [{}] — group: {} ===\n", now, grp);

        // Collect all flow keys from all instances that belong to this group
        let mut flow_keys: Vec<FlowKey> = Vec::new();
        for inst in &all_instances {
            for (key, entry) in &inst.flows {
                let src_grp = find_group(&entry.src_ip, &groups);
                let dst_grp = find_group(&entry.dst_ip, &groups);
                if (src_grp == grp || dst_grp == grp) && !flow_keys.contains(key) {
                    flow_keys.push(key.clone());
                }
            }
        }

        // Sort by max ART across instances
        flow_keys.sort_by(|a, b| {
            let art_a: f64 = all_instances.iter()
                .filter_map(|inst| inst.flows.get(a).map(|f| f.art_us))
                .fold(0.0f64, f64::max);
            let art_b: f64 = all_instances.iter()
                .filter_map(|inst| inst.flows.get(b).map(|f| f.art_us))
                .fold(0.0f64, f64::max);
            art_b.partial_cmp(&art_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        flow_keys.truncate(top);

        for key in &flow_keys {
            println!("Flow: {}:{} → {}:{}", key.src_ip, key.src_port, key.dst_ip, key.dst_port);

            // Header
            let inst_names: Vec<&str> = all_instances.iter()
                .filter(|i| i.flows.contains_key(key))
                .map(|i| i.name.as_str())
                .collect();

            if inst_names.is_empty() { continue; }

            print!("{:<20}", "");
            for name in &inst_names { print!(" {:>12}", name); }
            println!();
            print!("{:<20}", "────────────────────");
            for _ in &inst_names { print!(" {:>12}", "────────────"); }
            println!();

            // Rows
            let metrics: &[(&str, Box<dyn Fn(&aria_api::TcpRtEntry) -> String>)] = &[
                ("cRTT (us)", Box::new(|f: &aria_api::TcpRtEntry| format!("{:.1}", f.rtt_client_us))),
                ("sRTT (us)", Box::new(|f| format!("{:.1}", f.rtt_server_us))),
                ("ART (us)", Box::new(|f| format!("{:.1}", f.art_us))),
                ("ReqRT", Box::new(|f| format!("{}", f.retrans_req))),
                ("RspRT", Box::new(|f| format!("{}", f.retrans_resp))),
            ];

            for (label, extractor) in metrics {
                print!("{:<20}", label);
                for inst in &all_instances {
                    if let Some(f) = inst.flows.get(key) {
                        print!(" {:>12}", extractor(f));
                    }
                }
                println!();
            }

            // Breakdown (need at least 2 observation points)
            let points: Vec<(&str, &aria_api::TcpRtEntry)> = all_instances.iter()
                .filter_map(|i| i.flows.get(key).map(|f| (i.name.as_str(), f)))
                .collect();

            if points.len() >= 2 {
                println!("{:<20}", "────────────────────");
                println!("Latency Breakdown:");

                // Find bond/physical (first), tap-in (middle), tap-out (last by sRTT ascending)
                let mut sorted_points = points.clone();
                sorted_points.sort_by(|a, b| b.1.rtt_server_us.partial_cmp(&a.1.rtt_server_us).unwrap_or(std::cmp::Ordering::Equal));

                for i in 0..sorted_points.len() - 1 {
                    let (outer_name, outer) = sorted_points[i];
                    let (inner_name, inner) = sorted_points[i + 1];
                    let latency = (outer.art_us - outer.rtt_server_us) - (inner.art_us - inner.rtt_server_us);
                    let host_overhead = outer.rtt_server_us - inner.rtt_server_us;
                    println!("  {} → {}: network={:.1}us  processing={:.1}us",
                        outer_name, inner_name, host_overhead, latency.max(0.0));
                }

                // Last point (closest to server)
                let (last_name, last) = sorted_points.last().unwrap();
                let server_processing = last.art_us - last.rtt_server_us;
                println!("  {} → server: processing={:.1}us", last_name, server_processing.max(0.0));

                // Client-side (first point)
                let (first_name, first) = sorted_points.first().unwrap();
                println!("  client → {}: cRTT={:.1}us", first_name, first.rtt_client_us);

                // Packet loss
                println!("Packet Loss:");
                for i in 0..sorted_points.len() - 1 {
                    let (outer_name, outer) = sorted_points[i];
                    let (inner_name, inner) = sorted_points[i + 1];
                    let req_loss = outer.retrans_req as i64 - inner.retrans_req as i64;
                    let resp_loss = outer.retrans_resp as i64 - inner.retrans_resp as i64;
                    println!("  {} → {}: req={} resp={}", outer_name, inner_name, req_loss.max(0), resp_loss.max(0));
                }
                let (last_name, last) = sorted_points.last().unwrap();
                println!("  {} → server: req={} resp={}", last_name, last.retrans_req, last.retrans_resp);
            }
            println!();
        }

        if flow_keys.is_empty() {
            println!("No flows found for group '{}'", grp);
        }
    } else {
        // ── Per-group aggregated summary ──
        println!("=== TCP-RT Analysis [{}] ===\n", now);

        // Use the instance with the most flows for aggregation (typically tap-in or current)
        let best_inst = all_instances.iter()
            .max_by_key(|i| i.flows.len());

        let best_inst = match best_inst {
            Some(i) => i,
            None => { println!("No TCP-RT data collected yet"); return Ok(()); }
        };

        if best_inst.flows.is_empty() {
            println!("No TCP-RT data collected yet");
            return Ok(());
        }

        // Aggregate by group
        struct GroupAgg {
            flows: usize,
            crtt_vals: Vec<f64>,
            srtt_vals: Vec<f64>,
            art_vals: Vec<f64>,
            retrans_req: u32,
            retrans_resp: u32,
        }

        let mut agg: std::collections::HashMap<String, GroupAgg> = std::collections::HashMap::new();

        for (_key, entry) in &best_inst.flows {
            let grp = find_group(&entry.dst_ip, &groups);
            let g = agg.entry(grp).or_insert(GroupAgg {
                flows: 0, crtt_vals: Vec::new(), srtt_vals: Vec::new(),
                art_vals: Vec::new(), retrans_req: 0, retrans_resp: 0,
            });
            g.flows += 1;
            g.crtt_vals.push(entry.rtt_client_us);
            g.srtt_vals.push(entry.rtt_server_us);
            g.art_vals.push(entry.art_us);
            g.retrans_req += entry.retrans_req;
            g.retrans_resp += entry.retrans_resp;
        }

        // Sort by P95 ART descending
        let mut groups_sorted: Vec<(String, GroupAgg)> = agg.into_iter().collect();
        groups_sorted.sort_by(|a, b| {
            let mut a_arts = a.1.art_vals.clone(); a_arts.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            let mut b_arts = b.1.art_vals.clone(); b_arts.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&b_arts, 0.95).partial_cmp(&percentile(&a_arts, 0.95)).unwrap_or(std::cmp::Ordering::Equal)
        });

        println!("Per-Group Summary (from {}):", best_inst.name);
        println!("{:<15} {:>6} {:>12} {:>12} {:>12} {:>12} {:>8} {:>8}",
            "Group", "Flows", "Avg cRTT", "Avg sRTT", "Avg ART", "P95 ART", "ReqRT", "RspRT");
        println!("{:<15} {:>6} {:>12} {:>12} {:>12} {:>12} {:>8} {:>8}",
            "───────────────", "──────", "────────────", "────────────", "────────────", "────────────", "────────", "────────");

        for (name, g) in &groups_sorted {
            let avg_crtt = g.crtt_vals.iter().sum::<f64>() / g.flows as f64;
            let avg_srtt = g.srtt_vals.iter().sum::<f64>() / g.flows as f64;
            let avg_art = g.art_vals.iter().sum::<f64>() / g.flows as f64;
            let mut sorted_arts = g.art_vals.clone();
            sorted_arts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let p95_art = percentile(&sorted_arts, 0.95);
            println!("{:<15} {:>6} {:>12.1} {:>12.1} {:>12.1} {:>12.1} {:>8} {:>8}",
                name, g.flows, avg_crtt, avg_srtt, avg_art, p95_art, g.retrans_req, g.retrans_resp);
        }

        // Top N slowest flows
        let mut all_flows: Vec<&aria_api::TcpRtEntry> = best_inst.flows.values().collect();
        all_flows.sort_by(|a, b| b.art_us.partial_cmp(&a.art_us).unwrap_or(std::cmp::Ordering::Equal));
        all_flows.truncate(top);

        println!("\nSlowest Flows (top {} by ART):", top);
        println!("{:<20} {:<20} {:>6} {:>6} {:>12} {:>8} {:>8} {}",
            "Source", "Destination", "SPort", "DPort", "ART (us)", "ReqRT", "RspRT", "Group");
        println!("{:<20} {:<20} {:>6} {:>6} {:>12} {:>8} {:>8} {}",
            "────────────────────", "────────────────────", "──────", "──────", "────────────", "────────", "────────", "───────");

        for f in &all_flows {
            let grp = find_group(&f.dst_ip, &groups);
            println!("{:<20} {:<20} {:>6} {:>6} {:>12.1} {:>8} {:>8} {}",
                f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.art_us,
                f.retrans_req, f.retrans_resp, grp);
        }
    }

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
        Commands::Stats { rules, flows, top, qos, groups, mirror, tcprt } => {
            if !rules && !flows && !qos && !groups && !mirror && !tcprt {
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
            TcprtCommands::List { top } => {
                match client.list_tcprt(&instance, top).await {
                    Ok(resp) => {
                        if resp.flows.is_empty() {
                            println!("No TCP-RT data collected yet");
                        } else {
                            println!("{:<20} {:<20} {:<8} {:<8} {:<12} {:<12} {:<12} {:<12} {:<8} {:<8} {:<8} {}",
                                "Source", "Destination", "SPort", "DPort",
                                "HS (us)", "cRTT (us)", "sRTT (us)", "ART (us)",
                                "ReqRT", "RspRT", "Reqs", "State");
                            for e in &resp.flows {
                                println!("{:<20} {:<20} {:<8} {:<8} {:<12.1} {:<12.1} {:<12.1} {:<12.1} {:<8} {:<8} {:<8} {}",
                                    e.src_ip, e.dst_ip, e.src_port, e.dst_port,
                                    e.handshake_us, e.rtt_client_us, e.rtt_server_us, e.art_us,
                                    e.retrans_req, e.retrans_resp, e.request_count, e.state);
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
            TcprtCommands::Analyze { top, group, watch, interval } => {
                if watch {
                    loop {
                        print!("\x1B[2J\x1B[H"); // clear screen
                        if let Err(e) = run_analyze(&client, &instance, top, group.as_deref()).await {
                            eprintln!("Error: {}", e);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    }
                } else {
                    run_analyze(&client, &instance, top, group.as_deref()).await
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
