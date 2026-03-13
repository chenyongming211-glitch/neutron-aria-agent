use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};

mod instance;
mod tap_registry;
mod netlink;

#[derive(Parser)]
#[command(name = "aria-agent")]
#[command(about = "Aria Firewall Agent - multi-tap XDP firewall daemon")]
struct Args {
    #[arg(long, default_value = "/etc/aria-agent/config.toml")]
    config: PathBuf,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default = "default_ebpf_path")]
    ebpf_path: String,
    #[serde(default = "default_pin_path")]
    pin_path: String,
    #[serde(default = "default_state_path")]
    state_path: String,
    #[serde(default = "default_iface_pattern")]
    iface_pattern: String,
    #[serde(default = "default_max_port_policies")]
    #[allow(dead_code)]
    max_port_policies: u32,
}

fn default_ebpf_path() -> String {
    "/usr/local/lib/libebpf_firewall.so".to_string()
}

fn default_pin_path() -> String {
    "/sys/fs/bpf/aria".to_string()
}

fn default_state_path() -> String {
    "/var/lib/aria-agent".to_string()
}

fn default_iface_pattern() -> String {
    "^tap".to_string()
}

fn default_max_port_policies() -> u32 {
    16384
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ebpf_path: default_ebpf_path(),
            pin_path: default_pin_path(),
            state_path: default_state_path(),
            iface_pattern: default_iface_pattern(),
            max_port_policies: default_max_port_policies(),
        }
    }
}

fn load_config(path: &PathBuf) -> Config {
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                match toml::from_str(&contents) {
                    Ok(config) => {
                        println!("Loaded config from {:?}", path);
                        return config;
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to parse config {:?}: {}", path, e);
                        eprintln!("Using default configuration");
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to read config {:?}: {}", path, e);
                eprintln!("Using default configuration");
            }
        }
    } else {
        println!("Config file {:?} not found, using defaults", path);
    }
    Config::default()
}

#[tokio::main]
async fn main() {
    // Root privilege check
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: aria-agent must run as root");
        std::process::exit(1);
    }

    let args = Args::parse();
    let config = load_config(&args.config);

    println!("aria-agent starting...");
    println!("  eBPF path: {}", config.ebpf_path);
    println!("  Pin path:  {}", config.pin_path);
    println!("  State path: {}", config.state_path);
    println!("  Interface pattern: {}", config.iface_pattern);

    // Verify eBPF binary exists
    if !std::path::Path::new(&config.ebpf_path).exists() {
        eprintln!("Error: eBPF binary not found at {}", config.ebpf_path);
        std::process::exit(1);
    }

    // Create base directories
    std::fs::create_dir_all(&config.pin_path).ok();
    std::fs::create_dir_all(&config.state_path).ok();

    let registry = Arc::new(tap_registry::TapRegistry::new(
        &config.ebpf_path,
        &config.pin_path,
        &config.state_path,
        &config.iface_pattern,
    ));

    // Start netlink monitoring (includes initial scan + event listening + periodic reconciliation)
    let registry_clone = registry.clone();
    let netlink_task = tokio::spawn(async move {
        loop {
            if let Err(e) = netlink::monitor(registry_clone.clone()).await {
                eprintln!("Netlink monitor error: {}, restarting in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    println!("aria-agent running. Press Ctrl+C or send SIGTERM to stop.");

    // Wait for shutdown signal
    let mut sigterm = signal(SignalKind::terminate())
        .expect("failed to create SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt())
        .expect("failed to create SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => println!("\nReceived SIGTERM"),
        _ = sigint.recv() => println!("\nReceived SIGINT"),
    }

    println!("Shutting down aria-agent...");

    // Abort netlink monitor
    netlink_task.abort();

    // Graceful shutdown: detach all instances
    registry.shutdown().await;

    println!("aria-agent stopped");
}
