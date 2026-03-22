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
    /// Service chain topology management
    Chain {
        #[command(subcommand)]
        action: ChainCommands,
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
    /// SSL handshake observability
    Ssl {
        #[command(subcommand)]
        action: SslCommands,
    },
    /// Firewall configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Full-stack connection diagnostic
    Diagnose {
        #[arg(long, help = "Destination IP")]
        dst: String,
        #[arg(long, help = "Destination port")]
        dport: u16,
        #[arg(long, help = "Service chain for per-hop breakdown")]
        chain: Option<String>,
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
        #[arg(long, default_value = "art", help = "Sort dimension: art, crtt, srtt, hs, retrans, nqa")]
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
        #[arg(long, help = "Destination IP (service address)")]
        dst: String,
        #[arg(long, help = "Destination port (service port)")]
        dport: u16,
        #[arg(long, help = "Service chain name for per-hop breakdown")]
        chain: Option<String>,
    },
    /// ART latency distribution histogram
    Histogram,
    /// TCP state distribution and anomaly detection
    States,
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
enum ChainCommands {
    /// Create or update a service chain from JSON file
    Apply {
        #[arg(short, long, help = "JSON file with service chain definition")]
        file: String,
    },
    /// List all service chains
    List,
    /// Show service chain details
    Show {
        #[arg(help = "Service chain name")]
        name: String,
    },
    /// Delete a service chain
    Delete {
        #[arg(help = "Service chain name")]
        name: String,
    },
}

#[derive(Subcommand)]
enum TraceCommands {
    /// Start cross-instance packet trace
    Start {
        #[arg(long, help = "Tap instance (omit for all instances)")]
        tap: Option<String>,
        #[arg(long, default_value = "", help = "Source IP to trace")]
        src: String,
        #[arg(long, default_value = "", help = "Destination IP to trace")]
        dst: String,
        #[arg(long, default_value = "0", help = "Source port to trace")]
        sport: u16,
        #[arg(long, default_value = "0", help = "Destination port to trace")]
        dport: u16,
        #[arg(long, default_value = "", help = "Protocol: tcp, udp, icmp")]
        proto: String,
        #[arg(long, help = "Seconds to trace (omit for continuous)")]
        wait: Option<u64>,
        #[arg(long, help = "Service chain name for hop-ordered display")]
        chain: Option<String>,
    },
}

#[derive(Subcommand)]
enum SslCommands {
    /// List SSL handshake records
    List {
        #[arg(long, default_value = "100", help = "Number of records to show")]
        top: usize,
    },
    /// Flush all SSL handshake records
    Flush,
    /// List SSL HTTP request/response events
    Http {
        #[arg(long, default_value = "100", help = "Number of records to show")]
        top: usize,
    },
    /// Flush all SSL HTTP events
    HttpFlush,
    /// Enable global SSL observability (affects all processes)
    Enable,
    /// Disable global SSL observability
    Disable,
    /// Show global SSL observability status
    Status,
    /// List SSL errors (read/write failures)
    Errors {
        #[arg(long, default_value = "20", help = "Number of errors to show")]
        top: usize,
    },
    /// Flush all SSL errors
    ErrorsFlush,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current firewall configuration
    Show,
    /// Set a configuration value
    Set {
        #[arg(help = "Configuration key: conntrack, monitoring, acl, qos, mirror, tcprt, or ssl")]
        key: String,
        #[arg(help = "Value: on or off")]
        value: String,
    },
}

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

fn note_ssl_is_global(cli: &Cli) {
    if cli.tap.is_some() {
        eprintln!("Note: --tap is ignored for SSL observability commands; SSL data is host-global.");
    }
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
        "nqa" => -(entry.nqa_score as f64), // Negate so lower NQA sorts first (desc sort)
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
        nqa: u8,
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
                nqa: entry.nqa_score,
            });
        }
    }

    println!("{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10} {:<10} {:<10} {:<7} {:<7} {:<5} {}",
        "Source", "Destination", "SPort", "DPort", "Instance",
        "ART (us)", "cRTT", "sRTT", "HS", "ReqRT", "RspRT", "NQA", "State");
    for r in &rows {
        let art_str = if r.art == 0.0 { "-".to_string() } else { format!("{:.1}", r.art) };
        println!("{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10.1} {:<10.1} {:<10.1} {:<7} {:<7} {:<5} {}",
            r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.instance,
            art_str, r.crtt, r.srtt, r.hs, r.req_rt, r.rsp_rt, r.nqa, r.state);
    }

    Ok(())
}

async fn run_tcprt_flow(
    client: &api_client::ApiClient,
    dst: &str,
    dport: u16,
    chain: Option<&str>,
) -> Result<(), String> {
    // Fetch aggregated data via filter API
    let resp = client.filter_tcprt(&aria_api::TcpRtFilterRequest {
        dst_ip: dst.to_string(),
        dst_port: dport,
    }).await?;

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

    // Find the best instance with dual-observation data
    let dual_inst = resp.instances.iter()
        .find(|i| i.instance == "system" && i.avg_forward_platform_us > 0.0)
        .or_else(|| resp.instances.iter().find(|i| i.avg_forward_platform_us > 0.0));

    if let Some(inst) = dual_inst {
        let client_net = inst.avg_rtt_client_us;
        let fwd_platform = inst.avg_forward_platform_us;
        let server_net = inst.avg_server_network_us;
        let rev_platform = inst.avg_reverse_platform_us;
        let server_proc = (inst.avg_art_us - server_net).max(0.0);

        struct Segment { label: &'static str, value: f64 }
        let segments = [
            Segment { label: "Client Network", value: client_net },
            Segment { label: "Platform (forward)", value: fwd_platform },
            Segment { label: "Server Network", value: server_net },
            Segment { label: "Platform (reverse)", value: rev_platform },
            Segment { label: "Server Processing", value: server_proc },
        ];
        let max_val = segments.iter().map(|s| s.value).fold(0.0f64, f64::max);

        println!("  Latency Breakdown (avg)");
        println!("  ─────────────────────────  ────────────");
        for seg in &segments {
            let marker = if seg.value >= max_val && max_val > 0.0 { "  <- bottleneck" } else { "" };
            println!("  {:<25} {:>8.1} us{}", seg.label, seg.value, marker);
        }

        println!();
        println!("  Retransmissions (total)");
        println!("  ─────────────────────────  ─────────  ─────────");
        println!("  {:<25} {:<10} {}", "", "Req", "Resp");
        println!("  {:<25} {:<10} {}", "Total", inst.total_retrans_req, inst.total_retrans_resp);

        println!();
        println!("  NQA Score (avg): {:.0}", inst.avg_nqa_score);
        println!();
        return Ok(());
    }

    // No dual-observation: show per-instance metrics
    println!("  {:<15} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8} {:>5}",
        "Instance", "cRTT", "sRTT", "ART", "HS", "ReqRT", "RspRT", "NQA");
    println!("  {:<15} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8} {:>5}",
        "───────────", "────────", "────────", "────────", "────────", "──────", "──────", "─────");
    for inst in &resp.instances {
        println!("  {:<15} {:>8.1}us {:>8.1}us {:>8.1}us {:>8.1}us {:>8} {:>8} {:>5.0}",
            inst.instance,
            inst.avg_rtt_client_us, inst.avg_rtt_server_us,
            inst.avg_art_us, inst.avg_handshake_us,
            inst.total_retrans_req, inst.total_retrans_resp,
            inst.avg_nqa_score);
    }
    if resp.instances.len() > 1 {
        println!("\n  Tip: use --chain <name> for per-hop latency breakdown");
    }
    println!();

    Ok(())
}

/// Per-hop fine-grained breakdown using service chain topology
async fn run_tcprt_flow_with_chain(
    client: &api_client::ApiClient,
    dst: &str,
    dport: u16,
    chain_name: &str,
    resp: &aria_api::TcpRtFilterResponse,
    total_flows: u32,
) -> Result<(), String> {
    // Fetch chain definition
    let chain = client.get_chain(chain_name).await?;

    println!("Service: {}:{}  (chain: {}, {} flows)\n", dst, dport, chain_name, total_flows);

    // Build tap → hop_index mapping
    let mut tap_to_hop: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, hop) in chain.hops.iter().enumerate() {
        for tap in &hop.taps {
            tap_to_hop.insert(tap.tap.clone(), idx);
        }
    }

    // Group instances by hop index, take representative value (average across instances in same hop)
    let mut hop_data: Vec<Option<aria_api::TcpRtAggregatedEntry>> = vec![None; chain.hops.len()];
    let mut hop_counts: Vec<u32> = vec![0; chain.hops.len()];

    for inst in &resp.instances {
        if let Some(&hop_idx) = tap_to_hop.get(&inst.instance) {
            if let Some(ref mut existing) = hop_data[hop_idx] {
                // Accumulate for averaging
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

    // Average the accumulated values for hops with multiple instances
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

    // Collect hops that have data, in chain order
    struct HopPoint { name: String, data: aria_api::TcpRtAggregatedEntry }
    let points: Vec<HopPoint> = chain.hops.iter().enumerate()
        .filter_map(|(idx, hop)| {
            hop_data[idx].take().map(|d| HopPoint { name: hop.name.clone(), data: d })
        })
        .collect();

    if points.is_empty() {
        println!("  No matching data found for chain hops");
        return Ok(());
    }

    if points.len() < 2 {
        let p = &points[0];
        println!("  Only one hop has data: {}", p.name);
        println!("  Avg cRTT: {:.1} us, Avg sRTT: {:.1} us, Avg ART: {:.1} us",
            p.data.avg_rtt_client_us, p.data.avg_rtt_server_us, p.data.avg_art_us);
        return Ok(());
    }

    // Latency breakdown: client network + inter-hop segments + app processing
    struct Segment { label: String, value: f64 }
    let mut segments: Vec<Segment> = Vec::new();

    // Client network = cRTT of first hop
    segments.push(Segment {
        label: "Client Network".to_string(),
        value: points[0].data.avg_rtt_client_us,
    });

    // Inter-hop segments
    for i in 0..points.len() - 1 {
        let diff = (points[i].data.avg_rtt_server_us - points[i + 1].data.avg_rtt_server_us).max(0.0);
        segments.push(Segment {
            label: format!("{} → {}", points[i].name, points[i + 1].name),
            value: diff,
        });
    }

    // App processing = ART - sRTT of last hop
    let last = &points[points.len() - 1];
    segments.push(Segment {
        label: format!("{} → server", last.name),
        value: (last.data.avg_art_us - last.data.avg_rtt_server_us).max(0.0),
    });

    let max_val = segments.iter().map(|s| s.value).fold(0.0f64, f64::max);

    println!("  Latency Breakdown (avg)");
    println!("  ─────────────────────  ────────────");
    for seg in &segments {
        let marker = if seg.value >= max_val && max_val > 0.0 { "  ← bottleneck" } else { "" };
        println!("  {:<23} {:.1} us{}", seg.label, seg.value, marker);
    }

    // Packet loss breakdown
    println!();
    println!("  Packet Loss (total)");
    println!("  ─────────────────────  ─────────  ─────────");
    println!("  {:<23} {:<10} {}", "", "Req Loss", "Rsp Loss");
    for i in 0..points.len() - 1 {
        let req_loss = (points[i].data.total_retrans_req as i64 - points[i + 1].data.total_retrans_req as i64).max(0);
        let rsp_loss = (points[i].data.total_retrans_resp as i64 - points[i + 1].data.total_retrans_resp as i64).max(0);
        let label = format!("{} → {}", points[i].name, points[i + 1].name);
        println!("  {:<23} {:<10} {}", label, req_loss, rsp_loss);
    }
    let last = &points[points.len() - 1];
    let label = format!("{} → server", last.name);
    println!("  {:<23} {:<10} {}", label, last.data.total_retrans_req, last.data.total_retrans_resp);
    println!();

    Ok(())
}

/// Collect trace events from all taps, keyed by instance name.
async fn collect_trace_events(
    client: &api_client::ApiClient,
    taps: &[String],
) -> Result<std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>, String> {
    let mut all = std::collections::HashMap::new();
    for tap in taps {
        match client.list_trace(tap, 65536).await {
            Ok(resp) => { all.insert(tap.clone(), resp.events); }
            Err(_) => { all.insert(tap.clone(), Vec::new()); }
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
    println!("Trace: {} → {}  (live, Ctrl+C to stop)\n", src_label, dst_label);
    println!("  {:<20} {:<10} {:<10} {}",
        "Instance", "In", "Out", "Verdict");
    println!("  {:<20} {:<10} {:<10} {}",
        "────────────────", "────────", "────────", "──────────────");
    for tap in taps {
        let evts = events.get(tap.as_str()).map(|v| v.as_slice()).unwrap_or(&[]);
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
    println!("  {:<20} {:<10} {:<10} {}",
        "Instance", "In", "Out", "Verdict");
    println!("  {:<20} {:<10} {:<10} {}",
        "────────────────", "────────", "────────", "──────────────");
    for tap in taps {
        let evts = events.get(tap.as_str()).map(|v| v.as_slice()).unwrap_or(&[]);
        print_instance_summary(tap, evts);
    }

    // Detail section for instances with drops
    for tap in taps {
        let evts = events.get(tap.as_str()).map(|v| v.as_slice()).unwrap_or(&[]);
        let drops: Vec<&aria_api::TraceEventEntry> = evts.iter()
            .filter(|e| e.result.contains("drop"))
            .collect();
        if drops.is_empty() {
            continue;
        }
        println!("\n  Detail ({}):", tap);
        println!("  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
            "Seq", "Source", "Destination", "Proto", "Result", "Drop Reason", "Hook");
        for e in &drops {
            println!("  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                e.seq, e.src_ip, e.dst_ip, e.proto, e.result, e.drop_reason, e.hook);
        }
    }
}

fn print_instance_summary(tap: &str, evts: &[aria_api::TraceEventEntry]) {
    if evts.is_empty() {
        println!("  {:<20} {:<10} {:<10} {}",
            tap, "0 pkts", "0 pkts", "no data");
        return;
    }
    let ingress = evts.iter().filter(|e| e.direction == "ingress").count();
    let egress = evts.iter().filter(|e| e.direction == "egress").count();
    let has_drop = evts.iter().any(|e| e.result.contains("drop"));
    let verdict = if has_drop {
        let reason = evts.iter()
            .find(|e| e.result.contains("drop"))
            .map(|e| e.drop_reason.as_str())
            .unwrap_or("unknown");
        format!("← drop:{}", reason)
    } else {
        "pass".to_string()
    };
    println!("  {:<20} {:<10} {:<10} {}",
        tap,
        format!("{} pkts", ingress),
        format!("{} pkts", egress),
        verdict);
}

/// Represents a hop in the chain trace display, with its taps and aggregated event data.
struct ChainHopTrace {
    name: String,
    taps: Vec<(String, String)>, // (tap_name, role)
}

/// Build chain hop trace structure from a chain definition.
fn build_chain_hops(chain: &aria_api::ServiceChainEntry) -> Vec<ChainHopTrace> {
    chain.hops.iter().map(|hop| {
        ChainHopTrace {
            name: hop.name.clone(),
            taps: hop.taps.iter().map(|t| (t.tap.clone(), t.role.clone())).collect(),
        }
    }).collect()
}

/// Count ingress/egress packets for a set of events.
fn count_in_out(evts: &[aria_api::TraceEventEntry]) -> (usize, usize) {
    let ingress = evts.iter().filter(|e| e.direction == "ingress").count();
    let egress = evts.iter().filter(|e| e.direction == "egress").count();
    (ingress, egress)
}

/// Build a compact drop summary string grouped by (direction, reason), e.g. "✗ 40 acl_deny, 6 qos_drop"
fn format_drop_summary(evts: &[aria_api::TraceEventEntry]) -> String {
    let drops: Vec<&aria_api::TraceEventEntry> = evts.iter()
        .filter(|e| e.result.contains("drop"))
        .collect();
    if drops.is_empty() {
        return "-".to_string();
    }
    // Group by drop_reason, count each
    let mut reason_counts: Vec<(String, usize)> = Vec::new();
    for d in &drops {
        let reason = if d.drop_reason.is_empty() { "unknown" } else { &d.drop_reason };
        if let Some(entry) = reason_counts.iter_mut().find(|(r, _)| r == reason) {
            entry.1 += 1;
        } else {
            reason_counts.push((reason.to_string(), 1));
        }
    }
    // Sort by count descending
    reason_counts.sort_by(|a, b| b.1.cmp(&a.1));
    let parts: Vec<String> = reason_counts.iter()
        .map(|(r, c)| format!("{} {}", c, r))
        .collect();
    format!("\u{2717} {}", parts.join(", "))
}

/// Per-hop aggregated data for drop attribution.
struct HopAgg {
    total_in: usize,
    total_out: usize,
    /// Drop events grouped by (direction, reason) → count
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
                let reason = if e.drop_reason.is_empty() { "unknown".to_string() } else { e.drop_reason.clone() };
                if let Some(entry) = drop_groups.iter_mut().find(|(d, r, _)| d == &dir && r == &reason) {
                    entry.2 += 1;
                } else {
                    drop_groups.push((dir, reason, 1));
                }
            }
        }
        drop_groups.sort_by(|a, b| b.2.cmp(&a.2));
        hop_aggs.push(HopAgg { total_in: hop_in, total_out: hop_out, drop_groups });
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
            } else { "-".to_string() };
            let out_str = if out_cnt > 0 || role == "out" || role == "bidi" {
                format!("{} pkts", out_cnt)
            } else { "-".to_string() };

            println!("  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
                hop.name, tap_name, role, in_str, out_str, drop_str);
        }
    }
}

/// Print drop attribution annotations (★ internal drops, ↓ inter-hop loss).
fn print_drop_annotations(
    hops: &[ChainHopTrace],
    hop_aggs: &[HopAgg],
) {
    let mut has_annotation = false;
    for i in 0..hop_aggs.len() {
        // Internal drop: in > out (covers both partial and total drop)
        if hop_aggs[i].total_in > hop_aggs[i].total_out {
            let lost = hop_aggs[i].total_in - hop_aggs[i].total_out;
            if !has_annotation { println!(); has_annotation = true; }
            println!("  \u{2605} dropped {}/{} inside {}",
                lost, hop_aggs[i].total_in, hops[i].name);

            if hop_aggs[i].drop_groups.is_empty() {
                // Black-box drop: no eBPF drop events captured
                println!("    \u{2514}\u{2500} no drop reason captured (device internal block)");
            } else {
                // Has drop events: show tree-style breakdown by direction+reason
                let total_groups = hop_aggs[i].drop_groups.len();
                for (j, (dir, reason, cnt)) in hop_aggs[i].drop_groups.iter().enumerate() {
                    let connector = if j + 1 < total_groups { "\u{251c}\u{2500}" } else { "\u{2514}\u{2500}" };
                    println!("    {} {}: {} ({})", connector, dir, cnt, reason);
                }
            }
        }
        // Inter-hop loss
        if i + 1 < hop_aggs.len() && hop_aggs[i].total_out > 0 {
            let next_in = hop_aggs[i + 1].total_in;
            if hop_aggs[i].total_out > next_in {
                let lost = hop_aggs[i].total_out - next_in;
                if !has_annotation { println!(); has_annotation = true; }
                println!("  \u{2193} {} pkts lost between {} and {}",
                    lost, hops[i].name, hops[i + 1].name);
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
    println!("Chain: {}    Filter: {} \u{2192} {}\n", chain_name, src_label, dst_label);

    println!("  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "Hop", "Tap", "Role", "In", "Out", "Drops");
    println!("  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    print_chain_table_rows(hops, events);
    let hop_aggs = collect_hop_aggs(hops, events);
    print_drop_annotations(hops, &hop_aggs);

    // Detail section for drops
    for hop in hops {
        for (tap_name, _role) in &hop.taps {
            let evts = events.get(tap_name).map(|v| v.as_slice()).unwrap_or(&[]);
            let drops: Vec<&aria_api::TraceEventEntry> = evts.iter()
                .filter(|e| e.result.contains("drop"))
                .collect();
            if drops.is_empty() { continue; }
            println!("\n  Detail ({} / {}):", hop.name, tap_name);
            println!("  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                "Seq", "Source", "Destination", "Proto", "Result", "Drop Reason", "Hook");
            for e in &drops {
                println!("  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                    e.seq, e.src_ip, e.dst_ip, e.proto, e.result, e.drop_reason, e.hook);
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
    println!("Chain: {}    Filter: {} \u{2192} {}  (live, Ctrl+C to stop)\n", chain_name, src_label, dst_label);

    println!("  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "Hop", "Tap", "Role", "In", "Out", "Drops");
    println!("  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

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
    // Fetch chain definition
    let chain = client.get_chain(chain_name).await?;
    let hops = build_chain_hops(&chain);

    // Collect only the taps referenced by the chain
    let taps: Vec<String> = hops.iter()
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

    // Flush + start on all taps
    for tap in &taps {
        let _ = client.flush_trace(tap).await;
        client.start_trace(tap, &req).await
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
                    if !running.load(std::sync::atomic::Ordering::SeqCst) { break; }
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

    // Flush + start on all taps
    for tap in taps {
        let _ = client.flush_trace(tap).await;
        client.start_trace(tap, &req).await
            .map_err(|e| format!("Failed to start trace on {}: {}", tap, e))?;
    }

    let tap_list = taps.join(", ");
    println!("Tracing on [{}] ...", tap_list);

    let result = match wait {
        Some(secs) => {
            // Timed mode: sleep then collect
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let events = collect_trace_events(client, taps).await?;
            display_trace_summary(src, dst, &events, taps);
            Ok(())
        }
        None => {
            // Continuous mode: refresh every 2s, Ctrl+C to stop
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            });

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let events = collect_trace_events(client, taps).await?;
                // Clear screen and redraw
                print!("\x1B[2J\x1B[H");
                display_trace_live(src, dst, &events, taps);
                // Sleep 2s in small increments so we can break quickly on Ctrl+C
                for _ in 0..20 {
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }

            // Final collection and display
            println!();
            let events = collect_trace_events(client, taps).await?;
            display_trace_summary(src, dst, &events, taps);
            Ok(())
        }
    };

    // Stop trace on all taps
    for tap in taps {
        let _ = client.stop_trace(tap).await;
    }

    result
}

async fn run_diagnose(
    client: &api_client::ApiClient,
    instance: &str,
    dst: &str,
    dport: u16,
    _chain: Option<&str>,
) -> Result<(), String> {
    println!("=== Aria Diagnostic Report ===");
    println!("Target: {}:{}\n", dst, dport);

    // --- L4: TCP ---
    println!("--- L4: TCP ---");
    let tcprt_resp = client.filter_tcprt(&aria_api::TcpRtFilterRequest {
        dst_ip: dst.to_string(),
        dst_port: dport,
    }).await;

    match tcprt_resp {
        Ok(resp) if !resp.instances.is_empty() => {
            let total_flows: u32 = resp.instances.iter().map(|i| i.flow_count).sum();
            let fc = resp.instances.len() as f64;
            let avg_hs: f64 = resp.instances.iter().map(|i| i.avg_handshake_us).sum::<f64>() / fc;
            let avg_crtt: f64 = resp.instances.iter().map(|i| i.avg_rtt_client_us).sum::<f64>() / fc;
            let avg_srtt: f64 = resp.instances.iter().map(|i| i.avg_rtt_server_us).sum::<f64>() / fc;
            let total_retrans_req: u32 = resp.instances.iter().map(|i| i.total_retrans_req).sum();
            let total_retrans_resp: u32 = resp.instances.iter().map(|i| i.total_retrans_resp).sum();
            let avg_nqa: f64 = resp.instances.iter().map(|i| i.avg_nqa_score).sum::<f64>() / fc;

            println!("  Flows: {}    Avg HS: {:.1}us    Avg cRTT: {:.1}us    Avg sRTT: {:.1}us",
                total_flows, avg_hs, avg_crtt, avg_srtt);
            println!("  Retrans: {} req / {} resp    NQA: {:.0}",
                total_retrans_req, total_retrans_resp, avg_nqa);
        }
        _ => {
            println!("  (no TCP-RT data)");
        }
    }

    // --- L5: SSL/TLS ---
    println!("\n--- L5: SSL/TLS ---");
    match client.list_ssl(instance, 10000).await {
        Ok(resp) => {
            if resp.connections.is_empty() {
                println!("  (no SSL data)");
            } else {
                let total = resp.connections.len();
                let avg_hs: f64 = resp.connections.iter().map(|c| c.handshake_us).sum::<f64>() / total as f64;

                // Count SNIs
                let mut sni_counts: Vec<(String, usize)> = Vec::new();
                for c in &resp.connections {
                    if c.sni.is_empty() { continue; }
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
        Err(_) => { println!("  (SSL data unavailable)"); }
    }

    // --- L7: HTTP ---
    println!("\n--- L7: HTTP ---");
    match client.list_ssl_http(instance, 10000).await {
        Ok(resp) => {
            if resp.events.is_empty() {
                println!("  (no HTTP data)");
            } else {
                let total = resp.events.len();
                let avg_latency: f64 = resp.events.iter().map(|e| e.latency_us).sum::<f64>() / total as f64;

                // Status code counts
                let mut status_counts: Vec<(u16, usize)> = Vec::new();
                for e in &resp.events {
                    if let Some(entry) = status_counts.iter_mut().find(|(s, _)| *s == e.status_code) {
                        entry.1 += 1;
                    } else {
                        status_counts.push((e.status_code, 1));
                    }
                }
                status_counts.sort_by(|a, b| b.1.cmp(&a.1));

                println!("  Requests: {}    Avg Latency: {:.1}ms", total, avg_latency / 1000.0);
                let status_str: Vec<String> = status_counts.iter().take(5)
                    .map(|(s, c)| format!("{}({})", s, c)).collect();
                println!("  Status: {}", status_str.join(" "));

                // Top slowest requests
                let mut sorted = resp.events.clone();
                sorted.sort_by(|a, b| b.latency_us.partial_cmp(&a.latency_us).unwrap_or(std::cmp::Ordering::Equal));
                println!("  Slowest:");
                for e in sorted.iter().take(5) {
                    println!("    {:<6} {:<30} {:.1}ms", e.method, e.path, e.latency_us / 1000.0);
                }
            }
        }
        Err(_) => { println!("  (HTTP data unavailable)"); }
    }

    // --- Drops ---
    println!("\n--- Drops ---");
    match client.list_drops(instance).await {
        Ok(resp) => {
            if resp.drops.is_empty() {
                println!("  (none)");
            } else {
                for d in &resp.drops {
                    println!("  {}: {} pkts ({} bytes) - {} {}",
                        d.reason, d.packets, d.bytes, d.direction, d.proto);
                }
            }
        }
        Err(_) => { println!("  (drop data unavailable)"); }
    }

    // --- Verdict ---
    let mut verdict = "HEALTHY";
    let mut reasons: Vec<String> = Vec::new();

    // Check NQA
    if let Ok(resp) = client.filter_tcprt(&aria_api::TcpRtFilterRequest {
        dst_ip: dst.to_string(),
        dst_port: dport,
    }).await {
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

    // Check 5xx ratio
    if let Ok(resp) = client.list_ssl_http(instance, 10000).await {
        if !resp.events.is_empty() {
            let total = resp.events.len() as f64;
            let count_5xx = resp.events.iter().filter(|e| e.status_code >= 500 && e.status_code < 600).count() as f64;
            let pct = count_5xx / total * 100.0;
            if pct > 10.0 {
                verdict = "UNHEALTHY";
                reasons.push(format!("5xx={:.1}% (>10%)", pct));
            }
        }
    }

    // Check drops
    if let Ok(resp) = client.list_drops(instance).await {
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
            TcprtCommands::Flow { dst, dport, chain } => {
                run_tcprt_flow(&client, &dst, dport, chain.as_deref()).await
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
            TraceCommands::Start { tap, src, dst, sport, dport, proto, wait, chain } => {
                if let Some(chain_name) = chain {
                    // Chain-aware mode: trace only the chain's taps, display by hop
                    run_trace_with_chain(&client, &chain_name, &src, &dst, sport, dport, &proto, wait).await
                } else {
                    let taps = if let Some(t) = tap {
                        vec![t]
                    } else {
                        match client.list_instances().await {
                            Ok(resp) => resp.instances.iter()
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
                        run_trace(&client, &taps, &src, &dst, sport, dport, &proto, wait).await
                    }
                }
            }
        },
        Commands::Ssl { action } => match action {
            SslCommands::List { top } => {
                note_ssl_is_global(&cli);
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
                note_ssl_is_global(&cli);
                match client.flush_ssl(&instance).await {
                    Ok(resp) => { println!("Flushed {} SSL handshake entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Http { top } => {
                note_ssl_is_global(&cli);
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
                note_ssl_is_global(&cli);
                match client.flush_ssl_http(&instance).await {
                    Ok(resp) => { println!("Flushed {} SSL HTTP entries", resp.flushed); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Enable => {
                note_ssl_is_global(&cli);
                match client.update_ssl_config(true).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Disable => {
                note_ssl_is_global(&cli);
                match client.update_ssl_config(false).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Status => {
                note_ssl_is_global(&cli);
                match client.get_ssl_config().await {
                    Ok(cfg) => {
                        println!("Global SSL Observability: {}", if cfg.enabled { "ENABLED" } else { "DISABLED" });
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            SslCommands::Errors { top } => {
                note_ssl_is_global(&cli);
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
                note_ssl_is_global(&cli);
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
                    note_ssl_is_global(&cli);
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
            run_diagnose(&client, &instance, &dst, dport, chain.as_deref()).await
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
