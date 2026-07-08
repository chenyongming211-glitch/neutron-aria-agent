use clap::{Parser, Subcommand};

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";

#[derive(Parser)]
#[command(name = "ariactl")]
#[command(about = "eBPF/XDP Firewall Control Plane")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
    #[arg(long, env = "ARIA_API_URL", default_value = DEFAULT_API_URL, help = "aria-agent API URL")]
    pub(crate) api_url: String,
    #[arg(
        long,
        help = "Operate on a specific tap instance managed by aria-agent"
    )]
    pub(crate) tap: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
    /// Kernel drop observability
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
pub(crate) enum SystemCommands {
    Start {
        #[arg(short, long)]
        iface: String,
        #[arg(long, default_value = "16384")]
        max_port_policies: u32,
    },
    Stop,
}

#[derive(Subcommand)]
pub(crate) enum GroupCommands {
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
    /// List groups with statistics
    WithStats,
}

#[derive(Subcommand)]
pub(crate) enum PolicyCommands {
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
    /// List all policies
    List,
    /// List policies with statistics
    WithStats,
}

#[derive(Subcommand)]
pub(crate) enum ConntrackCommands {
    /// List active connections
    List,
    /// Flush all connections
    Flush,
}

#[derive(Subcommand)]
pub(crate) enum QosCommands {
    /// Add or update a QoS rate limit
    Add {
        #[arg(long, help = "Group name (or 'default' for global)")]
        group: String,
        #[arg(long, help = "Direction: ingress, egress, or both")]
        direction: String,
        #[arg(long, help = "Rate limit (e.g., 100mbps, 1gbps)")]
        rate: String,
        #[arg(
            long,
            default_value = "0",
            help = "Burst size (e.g., 1mb, 512kb). 0=auto"
        )]
        burst: String,
        #[arg(long, default_value = "0", help = "Priority (0=highest, 7=lowest)")]
        priority: u8,
        #[arg(
            long,
            default_value = "policing",
            help = "Mode: policing (drop excess, works everywhere) or shaping (EDT delay, needs FQ qdisc)"
        )]
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
    /// List QoS rules with statistics
    WithStats,
}

#[derive(Subcommand)]
pub(crate) enum MirrorCommands {
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
    /// List mirror rules with statistics
    WithStats,
}

#[derive(Subcommand)]
pub(crate) enum TcprtCommands {
    /// Cross-instance TopN summary sorted by a chosen metric
    Top {
        #[arg(
            long,
            default_value = "art",
            help = "Sort dimension: art, crtt, srtt, hs, retrans, nqa"
        )]
        by: String,
        #[arg(long, default_value = "10", help = "Number of top flows to show")]
        top: usize,
        #[arg(long, help = "Enable dynamic refresh mode (like top)")]
        watch: bool,
        #[arg(
            long,
            default_value = "2",
            help = "Refresh interval in seconds (with --watch)"
        )]
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
pub(crate) enum DropsCommands {
    /// List kernel drop statistics
    List {
        #[arg(long, help = "Filter by interface name")]
        iface: Option<String>,
        #[arg(long, default_value = "50", help = "Maximum number of entries to show")]
        top: usize,
        #[arg(long, help = "Include unattributed early drops")]
        include_unattributed: bool,
    },
    /// Flush kernel drop statistics
    Flush {
        #[arg(long, help = "Filter by interface name")]
        iface: Option<String>,
        #[arg(long, help = "Include unattributed early drops")]
        include_unattributed: bool,
        #[arg(long, help = "Actually perform the flush")]
        force: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChainCommands {
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
pub(crate) enum TraceCommands {
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
pub(crate) enum SslCommands {
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
pub(crate) enum ConfigCommands {
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
