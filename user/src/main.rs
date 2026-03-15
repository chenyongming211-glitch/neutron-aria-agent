use clap::{Parser, Subcommand};

mod api_client;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";

#[derive(Parser)]
#[command(name = "firewall-ctl")]
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

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = api_client::ApiClient::new(&cli.api_url);
    let instance = get_instance(&cli);

    let result: Result<(), String> = match cli.command {
        Commands::System { action } => match action {
            SystemCommands::Start { iface, max_port_policies } => {
                match client.system_start(&aria_api::SystemStartRequest {
                    iface,
                    max_port_policies,
                }).await {
                    Ok(resp) => { println!("{}", resp.message); Ok(()) }
                    Err(e) => Err(e),
                }
            }
            SystemCommands::Stop => {
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
                    std::io::stdin().read_to_string(&mut buf)
                        .map_err(|e| format!("Failed to read stdin: {}", e))?;
                    buf
                } else {
                    std::fs::read_to_string(&file)
                        .map_err(|e| format!("Failed to read file '{}': {}", file, e))?
                };

                let policies: Vec<aria_api::AddPolicyRequest> = serde_json::from_str(&json_str)
                    .map_err(|e| format!("Invalid JSON: {}", e))?;

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
        Commands::Stats { rules, flows, top } => {
            if !rules && !flows {
                // Show overview
                match client.stats_overview(&instance).await {
                    Ok(stats) => {
                        println!("=== Firewall Statistics ===");
                        println!("  Groups:     {}", stats.groups);
                        println!("  Policies:   {}", stats.policies);
                        println!("  QoS rules:  {}", stats.qos_rules);
                        println!("  Conntrack:  {} IPv4, {} IPv6", stats.conntrack_v4, stats.conntrack_v6);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                if rules {
                    match client.stats_rules(&instance).await {
                        Ok(resp) => {
                            println!("=== Per-Rule Statistics ===");
                            if resp.rules.is_empty() {
                                println!("  No rule statistics collected yet");
                            } else {
                                println!("{:<10} {:<10} {:<8} {:<10} {:<15} {}",
                                    "SrcID", "DstID", "Proto", "Direction", "Packets", "Bytes");
                                for e in &resp.rules {
                                    println!("{:<10} {:<10} {:<8} {:<10} {:<15} {}",
                                        e.src_id, e.dst_id, e.proto, e.direction,
                                        e.packets, e.bytes);
                                }
                            }
                            println!();
                        }
                        Err(e) => eprintln!("Error reading rule stats: {}", e),
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
                        Err(e) => eprintln!("Error reading flow stats: {}", e),
                    }
                }
                Ok(())
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
            QosCommands::Add { group, direction, rate, burst, priority } => {
                match client.add_qos(&instance, &aria_api::AddQosRequest {
                    group,
                    direction,
                    rate,
                    burst,
                    priority,
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
                            println!("{:<15} {:<10} {:<10} {:<15} {:<15} {}",
                                "Group", "GroupID", "Direction", "Rate (B/s)", "Burst (B)", "Priority");
                            for r in &resp.rules {
                                println!("{:<15} {:<10} {:<10} {:<15} {:<15} {}",
                                    r.group, r.group_id, r.direction, r.rate_bps, r.burst_bytes, r.priority);
                            }
                        }
                        Ok(())
                    }
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
                        println!("  qos:        {}", if cfg.qos { "on" } else { "off" });
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
                    },
                    "monitoring" | "mon" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: Some(enabled),
                    },
                    _ => {
                        eprintln!("Error: unknown config key '{}': must be 'conntrack' or 'monitoring'", key);
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
