use clap::{Parser, Subcommand};
use std::env;

mod common;
mod manager;
mod state;

const DEFAULT_EBPF_PATH: &str = "/usr/local/lib/libebpf_firewall.so";
const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/aria_firewall";
const DEFAULT_STATE_PATH: &str = "/var/run/ebpf-firewall";

const TAP_BASE_PIN_PATH: &str = "/sys/fs/bpf/aria";
const TAP_BASE_STATE_PATH: &str = "/var/lib/aria-agent";

fn get_ebpf_path() -> String {
    env::var("EBPF_FIREWALL_PATH").unwrap_or_else(|_| DEFAULT_EBPF_PATH.to_string())
}

fn get_pin_path() -> String {
    env::var("EBPF_FIREWALL_PIN_PATH").unwrap_or_else(|_| DEFAULT_PIN_PATH.to_string())
}

fn get_state_path() -> String {
    env::var("EBPF_FIREWALL_STATE_PATH").unwrap_or_else(|_| DEFAULT_STATE_PATH.to_string())
}

#[derive(Parser)]
#[command(name = "firewall-ctl")]
#[command(about = "eBPF/XDP Firewall Control Plane")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short = 'p', long, help = "Path to pin directory")]
    pin_path: Option<String>,
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
        #[arg(long, help = "Show conntrack table summary")]
        conntrack: bool,
        #[arg(long, help = "Show QoS token bucket status")]
        qos: bool,
        #[arg(long, default_value = "20", help = "Number of top flows to show")]
        top: usize,
    },
    /// List all tap instances managed by aria-agent
    Tap {
        #[command(subcommand)]
        action: TapCommands,
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
    /// Firewall configuration (conntrack/monitoring switches)
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Real-time monitoring
    Monitor {
        #[arg(long, default_value = "2", help = "Refresh interval in seconds")]
        interval: u64,
    },
}

#[derive(Subcommand)]
enum SystemCommands {
    Start {
        #[arg(short, long)]
        iface: String,
        #[arg(short = 'e', long, help = "Path to eBPF binary")]
        ebpf_path: Option<String>,
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
    List,
}

#[derive(Subcommand)]
enum TapCommands {
    /// List all tap instances (scan pin directory)
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
        #[arg(long, default_value = "egress", help = "Direction: ingress or egress")]
        direction: String,
        #[arg(long, help = "Rate limit (e.g., 100mbps, 1gbps)")]
        rate: String,
        #[arg(long, default_value = "0", help = "Burst size (e.g., 1mb, 512kb). 0=auto")]
        burst: String,
        #[arg(long, default_value = "0", help = "Priority (0=highest, 7=lowest)")]
        priority: u8,
    },
    /// Delete a QoS rate limit
    Delete {
        #[arg(long)]
        group: String,
        #[arg(long, default_value = "egress")]
        direction: String,
    },
    /// List all QoS rules
    List,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current firewall configuration
    Show,
    /// Set a configuration value
    Set {
        #[arg(help = "Configuration key: conntrack or monitoring")]
        key: String,
        #[arg(help = "Value: on or off")]
        value: String,
    },
}

fn parse_direction(s: &str) -> Result<u8, String> {
    match s.to_lowercase().as_str() {
        "ingress" | "in" => Ok(0),
        "egress" | "out" => Ok(1),
        _ => Err(format!("Invalid direction '{}': must be 'ingress' or 'egress'", s)),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Determine pin_path and state_path based on --tap flag
    let (pin_path, state_path) = if let Some(ref tap_name) = cli.tap {
        let pin = format!("{}/{}", TAP_BASE_PIN_PATH, tap_name);
        let state = format!("{}/{}", TAP_BASE_STATE_PATH, tap_name);
        (
            cli.pin_path.unwrap_or(pin),
            state,
        )
    } else {
        (
            cli.pin_path.unwrap_or_else(get_pin_path),
            get_state_path(),
        )
    };

    std::fs::create_dir_all(&state_path).ok();

    let state_manager = state::StateManager::new(&state_path);

    let result = match cli.command {
        Commands::System { action } => match action {
            SystemCommands::Start { iface, ebpf_path, max_port_policies } => {
                if cli.tap.is_some() {
                    eprintln!("Error: 'system start' is not supported in --tap mode. Use aria-agent to manage tap instances.");
                    std::process::exit(1);
                }
                if max_port_policies == 0 || max_port_policies > 65535 {
                    eprintln!("Error: max-port-policies must be between 1 and 65535");
                    std::process::exit(1);
                }
                let actual_ebpf_path = ebpf_path.unwrap_or_else(get_ebpf_path);
                if let Err(e) = state_manager.set_max_port_policies(max_port_policies) {
                    eprintln!("Warning: Failed to persist max_port_policies: {}", e);
                }
                manager::system_start(&iface, &actual_ebpf_path, &pin_path, max_port_policies, &state_path).await
            }
            SystemCommands::Stop => {
                if cli.tap.is_some() {
                    eprintln!("Error: 'system stop' is not supported in --tap mode. Use aria-agent to manage tap instances.");
                    std::process::exit(1);
                }
                manager::system_stop(&pin_path, &state_path).await
            }
        },
        Commands::Group { action } => match action {
            GroupCommands::Add { name, cidr } => {
                let prog_path = format!("{}/xdp_firewall", pin_path);
                if !std::path::Path::new(&prog_path).exists() {
                    eprintln!("Error: Firewall not started. Run 'system start' first.");
                    std::process::exit(1);
                }

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                let id = match state_manager.add_group(&name, &cidr) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("Error saving state: {}", e);
                        std::process::exit(1);
                    }
                };

                if let Err(e) = manager::add_network("src", &cidr, id, &pin_path, &get_ebpf_path()) {
                    let _ = state_manager.remove_cidr_from_group(&name, &cidr);
                    eprintln!("Error (src): {}", e);
                    std::process::exit(1);
                }
                if let Err(e) = manager::add_network("dst", &cidr, id, &pin_path, &get_ebpf_path()) {
                    let _ = manager::delete_network("src", &cidr, id, &pin_path, &get_ebpf_path());
                    let _ = state_manager.remove_cidr_from_group(&name, &cidr);
                    eprintln!("Error (dst): {}", e);
                    std::process::exit(1);
                }

                println!("Added group '{}' with id {}", name, id);
                Ok(())
            }
            GroupCommands::Delete { name } => {
                let group = match state_manager.get_group(&name) {
                    Ok(Some(g)) => g,
                    Ok(None) => {
                        eprintln!("Error: Group '{}' not found", name);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let rules = match state_manager.list_rules() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error reading rules: {}", e);
                        std::process::exit(1);
                    }
                };
                for rule in rules {
                    if rule.src_group_id == group.id || rule.dst_group_id == group.id {
                        eprintln!("Error: Group '{}' is referenced by a rule", name);
                        std::process::exit(1);
                    }
                }

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                let mut errors = Vec::new();
                for cidr in &group.cidrs {
                    if let Err(e) = manager::delete_network("src", cidr, group.id, &pin_path, &get_ebpf_path()) {
                        errors.push(format!("src {}: {}", cidr, e));
                    }
                    if let Err(e) = manager::delete_network("dst", cidr, group.id, &pin_path, &get_ebpf_path()) {
                        errors.push(format!("dst {}: {}", cidr, e));
                    }
                }
                if !errors.is_empty() {
                    eprintln!("Failed to delete some CIDRs from kernel:");
                    for err in errors {
                        eprintln!("  {}", err);
                    }
                    eprintln!("Group '{}' NOT deleted from state.", name);
                    std::process::exit(1);
                }
                if let Err(e) = state_manager.delete_group(&name) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                println!("Deleted group '{}'", name);
                Ok(())
            }
            GroupCommands::List => {
                match state_manager.list_groups() {
                    Ok(groups) => {
                        if groups.is_empty() {
                            println!("No groups configured");
                        } else {
                            println!("{:<10} {:<15} {}", "ID", "Name", "CIDRs");
                            for g in groups {
                                println!("{:<10} {:<15} {}", g.id, g.name, g.cidrs.join(", "));
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Policy { action } => match action {
            PolicyCommands::Add { src_group, dst_group, proto, action, ports, direction } => {
                let direction_num = match parse_direction(&direction) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let proto_num = match proto.to_lowercase().as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    "icmp" => 1,
                    "any" => 0,
                    _ => {
                        eprintln!("Error: invalid protocol '{}'", proto);
                        std::process::exit(1);
                    }
                };
                let action_num = match action.to_lowercase().as_str() {
                    "accept" | "pass" => 0,
                    "drop" | "deny" => 1,
                    _ => {
                        eprintln!("Error: invalid action '{}'", action);
                        std::process::exit(1);
                    }
                };
                let src_id = if src_group == "any" {
                    0
                } else {
                    match state_manager.get_group(&src_group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", src_group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };
                let dst_id = if dst_group == "any" {
                    0
                } else {
                    match state_manager.get_group(&dst_group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", dst_group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                let add_result = match state_manager.add_rule(src_id, dst_id, proto_num, action_num, ports.as_deref(), direction_num) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };

                if let Err(e) = manager::add_policy(src_id, dst_id, proto_num, action_num, ports.as_deref(), add_result.bitmap_idx, add_result.is_new_port_set, direction_num, &pin_path, &get_ebpf_path()) {
                    let _ = state_manager.remove_rule(src_id, dst_id, proto_num, direction_num);
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }

                if let Some((old_idx, ref ports_normalized)) = add_result.old_port_set_released {
                    if let Err(e) = manager::delete_port_set(old_idx, ports_normalized, &pin_path, &get_ebpf_path()) {
                        eprintln!("Warning: failed to clean old port bitmap: {}", e);
                    }
                }

                println!("Added policy: {} -> {} ({})", src_group, dst_group, direction);
                Ok(())
            }
            PolicyCommands::Delete { src_group, dst_group, proto, direction } => {
                let direction_num = match parse_direction(&direction) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let proto_num = match proto.to_lowercase().as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    "icmp" => 1,
                    "any" => 0,
                    _ => {
                        eprintln!("Error: invalid protocol '{}'", proto);
                        std::process::exit(1);
                    }
                };
                let src_id = if src_group == "any" {
                    0
                } else {
                    match state_manager.get_group(&src_group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", src_group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };
                let dst_id = if dst_group == "any" {
                    0
                } else {
                    match state_manager.get_group(&dst_group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", dst_group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                if let Err(e) = manager::delete_policy(src_id, dst_id, proto_num, direction_num, &pin_path, &get_ebpf_path()) {
                    eprintln!("Error deleting from kernel: {}", e);
                    std::process::exit(1);
                }

                let remove_result = match state_manager.remove_rule(src_id, dst_id, proto_num, direction_num) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error removing from state: {}", e);
                        std::process::exit(1);
                    }
                };

                if let (Some(idx), Some(ref ports_normalized)) = (remove_result.bitmap_idx, &remove_result.port_set_released) {
                    if let Err(e) = manager::delete_port_set(idx, ports_normalized, &pin_path, &get_ebpf_path()) {
                        eprintln!("Warning: failed to clean port bitmap: {}", e);
                    }
                }

                println!("Deleted policy: {} -> {} proto {} ({})", src_group, dst_group, proto, direction);
                Ok(())
            }
            PolicyCommands::List => {
                match state_manager.list_rules() {
                    Ok(rules) => {
                        if rules.is_empty() {
                            println!("No policies configured");
                        } else {
                            println!("{:<10} {:<10} {:<8} {:<8} {:<10} {:<8} {}",
                                "SrcID", "DstID", "Proto", "Action", "Direction", "Bitmap", "Ports");
                            for rule in rules {
                                let action_str = if rule.action == 0 { "allow" } else { "drop" };
                                let dir_str = if rule.direction == 1 { "egress" } else { "ingress" };
                                let ports_str = rule.ports.as_deref().unwrap_or("");
                                let bitmap_str = match rule.bitmap_idx {
                                    Some(idx) => idx.to_string(),
                                    None => "-".to_string(),
                                };
                                println!("{:<10} {:<10} {:<8} {:<8} {:<10} {:<8} {}",
                                    rule.src_group_id, rule.dst_group_id,
                                    rule.proto, action_str, dir_str, bitmap_str, ports_str);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Stats { rules, flows, conntrack, qos, top } => {
            // If no specific flag, show the basic stats
            if !rules && !flows && !conntrack && !qos {
                return match manager::show_stats(&pin_path, &state_path) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
            }

            if rules {
                match aria_core::monitoring::get_rule_stats(&pin_path) {
                    Ok(entries) => {
                        println!("=== Per-Rule Statistics ===");
                        if entries.is_empty() {
                            println!("  No rule statistics collected yet");
                        } else {
                            println!("{:<10} {:<10} {:<8} {:<10} {:<15} {}",
                                "SrcID", "DstID", "Proto", "Direction", "Packets", "Bytes");
                            for e in &entries {
                                let dir = aria_core::monitoring::direction_name(e.key.direction);
                                let proto = aria_core::monitoring::proto_name(e.key.proto);
                                println!("{:<10} {:<10} {:<8} {:<10} {:<15} {}",
                                    e.key.src_id, e.key.dst_id, proto, dir,
                                    e.packets, aria_core::monitoring::format_bytes(e.bytes));
                            }
                        }
                        println!();
                    }
                    Err(e) => eprintln!("Error reading rule stats: {}", e),
                }
            }

            if flows {
                // IPv4 flows
                match aria_core::monitoring::get_top_flows_v4(&pin_path, top) {
                    Ok(entries) => {
                        println!("=== Top {} Flows (IPv4) ===", top);
                        if entries.is_empty() {
                            println!("  No IPv4 flow statistics collected yet");
                        } else {
                            println!("{:<18} {:<18} {:<8} {:<8} {:<8} {:<15} {}",
                                "Source", "Destination", "SPort", "DPort", "Proto", "Packets", "Bytes");
                            for e in &entries {
                                let proto = aria_core::monitoring::proto_name(e.proto);
                                println!("{:<18} {:<18} {:<8} {:<8} {:<8} {:<15} {}",
                                    e.src_ip, e.dst_ip, e.src_port, e.dst_port, proto,
                                    e.packets, aria_core::monitoring::format_bytes(e.bytes));
                            }
                        }
                        println!();
                    }
                    Err(e) => eprintln!("Error reading IPv4 flow stats: {}", e),
                }

                // IPv6 flows
                match aria_core::monitoring::get_top_flows_v6(&pin_path, top) {
                    Ok(entries) => {
                        println!("=== Top {} Flows (IPv6) ===", top);
                        if entries.is_empty() {
                            println!("  No IPv6 flow statistics collected yet");
                        } else {
                            println!("{:<39} {:<39} {:<8} {:<8} {:<8} {:<15} {}",
                                "Source", "Destination", "SPort", "DPort", "Proto", "Packets", "Bytes");
                            for e in &entries {
                                let proto = aria_core::monitoring::proto_name(e.proto);
                                println!("{:<39} {:<39} {:<8} {:<8} {:<8} {:<15} {}",
                                    e.src_ip, e.dst_ip, e.src_port, e.dst_port, proto,
                                    e.packets, aria_core::monitoring::format_bytes(e.bytes));
                            }
                        }
                        println!();
                    }
                    Err(e) => eprintln!("Error reading IPv6 flow stats: {}", e),
                }
            }

            if conntrack {
                match aria_core::monitoring::get_conntrack_stats(&pin_path) {
                    Ok(summary) => {
                        println!("=== Connection Tracking ===");
                        println!("  IPv4 connections: {}", summary.total_v4);
                        println!("  IPv6 connections: {}", summary.total_v6);
                        println!("  State NEW: {}", summary.new_count);
                        println!("  State ESTABLISHED: {}", summary.established_count);
                        println!();
                    }
                    Err(e) => eprintln!("Error reading conntrack stats: {}", e),
                }
            }

            if qos {
                match aria_core::qos_ops::list_qos_rules(&pin_path) {
                    Ok(entries) => {
                        println!("=== QoS Configuration ===");
                        if entries.is_empty() {
                            println!("  No QoS rules configured");
                        } else {
                            println!("{:<12} {:<10} {:<15} {:<15} {}",
                                "GroupID", "Direction", "Rate (B/s)", "Burst (B)", "Priority");
                            for (key, config) in &entries {
                                let dir = aria_core::monitoring::direction_name(key.direction);
                                println!("{:<12} {:<10} {:<15} {:<15} {}",
                                    key.group_id, dir, config.rate_bps, config.burst_bytes, config.priority);
                            }
                        }
                        println!();
                    }
                    Err(e) => eprintln!("Error reading QoS config: {}", e),
                }
            }

            Ok(())
        },
        Commands::Conntrack { action } => match action {
            ConntrackCommands::List => {
                match aria_core::ct_ops::ct_list(&pin_path) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            println!("No active connections");
                        } else {
                            println!("{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                                "Source", "Destination", "SPort", "DPort", "Proto", "State",
                                "Packets", "Bytes");
                            for e in &entries {
                                let state_str = match e.state {
                                    1 => "NEW",
                                    2 => "ESTABLISHED",
                                    _ => "UNKNOWN",
                                };
                                let proto = aria_core::monitoring::proto_name(e.proto);
                                println!("{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                                    e.src_ip, e.dst_ip, e.src_port, e.dst_port, proto,
                                    state_str, e.pkt_count,
                                    aria_core::monitoring::format_bytes(e.byte_count));
                            }
                            println!("\nTotal: {} connections", entries.len());
                        }
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            ConntrackCommands::Flush => {
                match aria_core::ct_ops::ct_flush(&pin_path) {
                    Ok(count) => {
                        println!("Flushed {} connections", count);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Qos { action } => match action {
            QosCommands::Add { group, direction, rate, burst, priority } => {
                let direction_num = match parse_direction(&direction) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let rate_bps = match aria_core::qos_ops::parse_rate(&rate) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let burst_bytes = if burst == "0" {
                    0 // auto
                } else {
                    match aria_core::qos_ops::parse_burst(&burst) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let group_id = if group == "default" || group == "any" {
                    0
                } else {
                    match state_manager.get_group(&group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                // Write to kernel map
                if let Err(e) = aria_core::qos_ops::add_qos_rule(group_id, direction_num, rate_bps, burst_bytes, priority, &pin_path) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }

                // Persist to state
                if let Err(e) = state_manager.add_qos_rule(&group, group_id, direction_num, rate_bps, burst_bytes, priority) {
                    eprintln!("Warning: failed to persist QoS rule: {}", e);
                }

                println!("Added QoS rule: group={} direction={} rate={} B/s burst={} B priority={}",
                    group, direction, rate_bps, burst_bytes, priority);
                Ok(())
            }
            QosCommands::Delete { group, direction } => {
                let direction_num = match parse_direction(&direction) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };

                let group_id = if group == "default" || group == "any" {
                    0
                } else {
                    match state_manager.get_group(&group) {
                        Ok(Some(g)) => g.id,
                        Ok(None) => {
                            eprintln!("Error: group '{}' not found", group);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let _ops_lock = match state_manager.acquire_ops_lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error acquiring ops lock: {}", e);
                        std::process::exit(1);
                    }
                };

                if let Err(e) = aria_core::qos_ops::delete_qos_rule(group_id, direction_num, &pin_path) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }

                if let Err(e) = state_manager.remove_qos_rule(group_id, direction_num) {
                    eprintln!("Warning: failed to remove QoS rule from state: {}", e);
                }

                println!("Deleted QoS rule: group={} direction={}", group, direction);
                Ok(())
            }
            QosCommands::List => {
                match state_manager.list_qos_rules() {
                    Ok(rules) => {
                        if rules.is_empty() {
                            println!("No QoS rules configured");
                        } else {
                            println!("{:<15} {:<10} {:<10} {:<15} {:<15} {}",
                                "Group", "GroupID", "Direction", "Rate (B/s)", "Burst (B)", "Priority");
                            for r in &rules {
                                let dir = if r.direction == 1 { "egress" } else { "ingress" };
                                println!("{:<15} {:<10} {:<10} {:<15} {:<15} {}",
                                    r.group_name, r.group_id, dir, r.rate_bps, r.burst_bytes, r.priority);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Config { action } => match action {
            ConfigCommands::Show => {
                let prog_path = format!("{}/xdp_firewall", pin_path);
                if !std::path::Path::new(&prog_path).exists() {
                    eprintln!("Error: Firewall not started. Run 'system start' first.");
                    std::process::exit(1);
                }

                // Read from kernel map
                match aria_core::ebpf_ops::read_firewall_config(&pin_path) {
                    Ok(cfg) => {
                        println!("=== Firewall Configuration ===");
                        println!("  conntrack:  {}", if cfg.conntrack_enabled != 0 { "on" } else { "off" });
                        println!("  monitoring: {}", if cfg.monitoring_enabled != 0 { "on" } else { "off" });
                        println!("  qos:        {}", if cfg.qos_enabled != 0 { "on" } else { "off" });
                        println!("  num_cpus:   {}", cfg.num_cpus);
                    }
                    Err(e) => {
                        // Fallback to state file
                        match state_manager.get_config() {
                            Ok((ct, mon)) => {
                                println!("=== Firewall Configuration (from state) ===");
                                println!("  conntrack:  {}", if ct { "on" } else { "off" });
                                println!("  monitoring: {}", if mon { "on" } else { "off" });
                                eprintln!("  (kernel map unavailable: {})", e);
                            }
                            Err(e2) => {
                                eprintln!("Error: {}", e2);
                                std::process::exit(1);
                            }
                        }
                    }
                }
                Ok(())
            }
            ConfigCommands::Set { key, value } => {
                let prog_path = format!("{}/xdp_firewall", pin_path);
                if !std::path::Path::new(&prog_path).exists() {
                    eprintln!("Error: Firewall not started. Run 'system start' first.");
                    std::process::exit(1);
                }

                let enabled = match value.to_lowercase().as_str() {
                    "on" | "true" | "1" | "yes" => true,
                    "off" | "false" | "0" | "no" => false,
                    _ => {
                        eprintln!("Error: invalid value '{}': must be 'on' or 'off'", value);
                        std::process::exit(1);
                    }
                };

                let (ct_opt, mon_opt) = match key.to_lowercase().as_str() {
                    "conntrack" | "ct" => (Some(enabled), None),
                    "monitoring" | "mon" => (None, Some(enabled)),
                    _ => {
                        eprintln!("Error: unknown config key '{}': must be 'conntrack' or 'monitoring'", key);
                        std::process::exit(1);
                    }
                };

                // Update kernel map
                if let Err(e) = aria_core::ebpf_ops::update_firewall_config(&pin_path, ct_opt, mon_opt) {
                    eprintln!("Error updating kernel config: {}", e);
                    std::process::exit(1);
                }

                // Persist to state
                if let Some(ct) = ct_opt {
                    if let Err(e) = state_manager.set_conntrack_enabled(ct) {
                        eprintln!("Warning: failed to persist config: {}", e);
                    }
                }
                if let Some(mon) = mon_opt {
                    if let Err(e) = state_manager.set_monitoring_enabled(mon) {
                        eprintln!("Warning: failed to persist config: {}", e);
                    }
                }

                println!("Set {} = {}", key, if enabled { "on" } else { "off" });
                Ok(())
            }
        },
        Commands::Monitor { interval } => {
            println!("Monitoring (refresh every {}s, press Ctrl+C to stop)...", interval);
            loop {
                // Clear screen
                print!("\x1b[2J\x1b[H");

                println!("=== Aria Firewall Monitor ===\n");

                // Conntrack summary
                if let Ok(summary) = aria_core::monitoring::get_conntrack_stats(&pin_path) {
                    println!("Connections: {} IPv4, {} IPv6 (NEW: {}, ESTABLISHED: {})",
                        summary.total_v4, summary.total_v6, summary.new_count, summary.established_count);
                }

                // Top 10 flows (IPv4)
                if let Ok(flows_v4) = aria_core::monitoring::get_top_flows_v4(&pin_path, 10) {
                    println!("\nTop 10 Flows (IPv4):");
                    if flows_v4.is_empty() {
                        println!("  (none)");
                    } else {
                        println!("  {:<18} {:<18} {:<8} {:<8} {:<8} {:<12} {}",
                            "Source", "Dest", "SPort", "DPort", "Proto", "Packets", "Bytes");
                        for f in &flows_v4 {
                            println!("  {:<18} {:<18} {:<8} {:<8} {:<8} {:<12} {}",
                                f.src_ip, f.dst_ip, f.src_port, f.dst_port,
                                aria_core::monitoring::proto_name(f.proto),
                                f.packets, aria_core::monitoring::format_bytes(f.bytes));
                        }
                    }
                }

                // Top 10 flows (IPv6)
                if let Ok(flows_v6) = aria_core::monitoring::get_top_flows_v6(&pin_path, 10) {
                    println!("\nTop 10 Flows (IPv6):");
                    if flows_v6.is_empty() {
                        println!("  (none)");
                    } else {
                        println!("  {:<39} {:<39} {:<8} {:<8} {:<8} {:<12} {}",
                            "Source", "Dest", "SPort", "DPort", "Proto", "Packets", "Bytes");
                        for f in &flows_v6 {
                            println!("  {:<39} {:<39} {:<8} {:<8} {:<8} {:<12} {}",
                                f.src_ip, f.dst_ip, f.src_port, f.dst_port,
                                aria_core::monitoring::proto_name(f.proto),
                                f.packets, aria_core::monitoring::format_bytes(f.bytes));
                        }
                    }
                }

                // Rule stats (top 10 by bytes)
                if let Ok(mut entries) = aria_core::monitoring::get_rule_stats(&pin_path) {
                    entries.truncate(10);
                    println!("\nTop 10 Rules:");
                    if entries.is_empty() {
                        println!("  (none)");
                    } else {
                        println!("  {:<10} {:<10} {:<8} {:<10} {:<12} {}",
                            "SrcID", "DstID", "Proto", "Direction", "Packets", "Bytes");
                        for e in &entries {
                            println!("  {:<10} {:<10} {:<8} {:<10} {:<12} {}",
                                e.key.src_id, e.key.dst_id,
                                aria_core::monitoring::proto_name(e.key.proto),
                                aria_core::monitoring::direction_name(e.key.direction),
                                e.packets, aria_core::monitoring::format_bytes(e.bytes));
                        }
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
            }
        },
        Commands::Tap { action } => match action {
            TapCommands::List => {
                let base_pin = TAP_BASE_PIN_PATH;
                let base_pin_path = std::path::Path::new(base_pin);
                if !base_pin_path.exists() {
                    println!("No tap instances found (pin directory {} does not exist)", base_pin);
                    return;
                }
                let entries = match std::fs::read_dir(base_pin_path) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error reading pin directory: {}", e);
                        std::process::exit(1);
                    }
                };
                let mut taps: Vec<String> = Vec::new();
                for entry in entries {
                    if let Ok(entry) = entry {
                        if entry.path().is_dir() {
                            if let Some(name) = entry.file_name().to_str() {
                                taps.push(name.to_string());
                            }
                        }
                    }
                }
                taps.sort();
                if taps.is_empty() {
                    println!("No tap instances found");
                } else {
                    println!("{:<20} {:<10} {}", "TAP", "Maps", "State");
                    for tap in &taps {
                        let pin_dir = format!("{}/{}", base_pin, tap);
                        let state_dir = format!("{}/{}", TAP_BASE_STATE_PATH, tap);
                        let maps_ok = std::path::Path::new(&format!("{}/POLICY_TABLE", pin_dir)).exists();
                        let state_ok = std::path::Path::new(&format!("{}/state.json", state_dir)).exists();
                        let maps_str = if maps_ok { "ok" } else { "missing" };
                        let state_str = if state_ok { "ok" } else { "missing" };
                        println!("{:<20} {:<10} {}", tap, maps_str, state_str);
                    }
                }
                Ok(())
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
