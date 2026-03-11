use clap::{Parser, Subcommand};
use std::env;

mod common;
mod manager;
mod state;

const DEFAULT_EBPF_PATH: &str = "/root/ebpf-firewall/ebpf/target/bpfel-unknown-none/release/ebpf-firewall";
const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/aria_firewall";
const DEFAULT_STATE_PATH: &str = "/var/run/ebpf-firewall";

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
    Stats,
}

#[derive(Subcommand)]
enum SystemCommands {
    Start {
        #[arg(short, long)]
        iface: String,
        #[arg(short = 'e', long, help = "Path to eBPF binary")]
        ebpf_path: Option<String>,
        #[arg(long, default_value = "64")]
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
        #[arg(short, long)]
        ports: Option<String>,
    },
    List,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let pin_path = cli.pin_path.unwrap_or_else(get_pin_path);
    let state_path = get_state_path();

    std::fs::create_dir_all(&state_path).ok();

    let state_manager = state::StateManager::new(&state_path);

    let result = match cli.command {
        Commands::System { action } => match action {
            SystemCommands::Start { iface, ebpf_path, max_port_policies } => {
                let actual_ebpf_path = ebpf_path.unwrap_or_else(get_ebpf_path);
                // 先持久化 max_port_policies，replay 读取 state.json 时即可用
                if let Err(e) = state_manager.set_max_port_policies(max_port_policies) {
                    eprintln!("Warning: Failed to persist max_port_policies: {}", e);
                }
                manager::system_start(&iface, &actual_ebpf_path, &pin_path, max_port_policies, &state_path).await
            }
            SystemCommands::Stop => manager::system_stop(&pin_path).await,
        },
        Commands::Group { action } => match action {
            GroupCommands::Add { name, cidr } => {
                // 先检查防火墙是否启动
                let prog_path = format!("{}/xdp_firewall", pin_path);
                if !std::path::Path::new(&prog_path).exists() {
                    eprintln!("Error: Firewall not started. Run 'system start' first.");
                    std::process::exit(1);
                }

                // 1. 先写状态，获取唯一 ID
                let id = match state_manager.add_group(&name, &cidr) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("Error saving state: {}", e);
                        std::process::exit(1);
                    }
                };

                // 2. 用正确的 ID 写内核
                if let Err(e) = manager::add_network("src", &cidr, id, &pin_path, &get_ebpf_path()).await {
                    // 回滚状态
                    let _ = state_manager.remove_cidr_from_group(&name, &cidr);
                    eprintln!("Error (src): {}", e);
                    std::process::exit(1);
                }
                if let Err(e) = manager::add_network("dst", &cidr, id, &pin_path, &get_ebpf_path()).await {
                    // 回滚：删除 src 内核条目 + 状态
                    let _ = manager::delete_network("src", &cidr, id, &pin_path, &get_ebpf_path()).await;
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
                let rules = state_manager.list_rules().unwrap_or_default();
                for rule in rules {
                    if rule.src_group_id == group.id || rule.dst_group_id == group.id {
                        eprintln!("Error: Group '{}' is referenced by a rule", name);
                        std::process::exit(1);
                    }
                }
                let mut errors = Vec::new();
                for cidr in &group.cidrs {
                    if let Err(e) = manager::delete_network("src", cidr, group.id, &pin_path, &get_ebpf_path()).await {
                        errors.push(format!("src {}: {}", cidr, e));
                    }
                    if let Err(e) = manager::delete_network("dst", cidr, group.id, &pin_path, &get_ebpf_path()).await {
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
            PolicyCommands::Add { src_group, dst_group, proto, action, ports } => {
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
                // 1. 写状态，获取 bitmap_idx 和 is_new_port_set
                let add_result = match state_manager.add_rule(src_id, dst_id, proto_num, action_num, ports.as_deref()) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };

                // 2. 写内核（只在新端口集时写位图）
                if let Err(e) = manager::add_policy(src_id, dst_id, proto_num, action_num, ports.as_deref(), add_result.bitmap_idx, add_result.is_new_port_set, &pin_path, &get_ebpf_path()).await {
                    // 回滚状态
                    let _ = state_manager.remove_rule(src_id, dst_id, proto_num);
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                println!("Added policy: {} -> {}", src_group, dst_group);
                Ok(())
            }
            PolicyCommands::List => {
                match state_manager.list_rules() {
                    Ok(rules) => {
                        if rules.is_empty() {
                            println!("No policies configured");
                        } else {
                            println!("{:<10} {:<10} {:<8} {:<8} {:<8?} {}",
                                "SrcID", "DstID", "Proto", "Action", "Bitmap", "Ports");
                            for rule in rules {
                                let action_str = if rule.action == 0 { "allow" } else { "drop" };
                                let ports_str = rule.ports.as_deref().unwrap_or("");
                                println!("{:<10} {:<10} {:<8} {:<8} {:<8?} {}",
                                    rule.src_group_id, rule.dst_group_id,
                                    rule.proto, action_str, rule.bitmap_idx, ports_str);
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
        Commands::Stats => manager::show_stats(&pin_path).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}