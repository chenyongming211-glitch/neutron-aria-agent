use clap::Parser;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::EnvFilter;

mod api_handlers;
mod api_routes;
mod control_plane;
mod ebpf_binary;
mod instance;
mod kernel_drop_manager;
mod kernel_drop_support;
mod netlink;
mod openapi;
mod service_chain;
mod ssl_manager;
mod ssl_support;
mod system_manager;
mod tap_registry;
mod trace_backend;

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
    #[serde(default = "default_trace_backend")]
    trace_backend: String,
    #[serde(default = "default_trace_auto_allow_ringbuf")]
    trace_auto_allow_ringbuf: bool,
    #[serde(default = "default_pin_path")]
    pin_path: String,
    #[serde(default = "default_state_path")]
    state_path: String,
    #[serde(default = "default_iface_pattern")]
    iface_pattern: String,
    #[serde(default = "default_max_port_policies")]
    max_port_policies: u32,
    #[serde(default = "default_listen_addr")]
    listen_addr: String,
    #[serde(default = "default_log_format")]
    log_format: String,
    #[serde(default = "default_log_filter")]
    log_filter: String,
    #[serde(default = "default_log_file_path")]
    log_file_path: String,
}

fn default_ebpf_path() -> String {
    "/usr/local/lib/libebpf_firewall.so".to_string()
}

fn default_trace_backend() -> String {
    "auto".to_string()
}

fn default_trace_auto_allow_ringbuf() -> bool {
    false
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

fn default_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_log_filter() -> String {
    "info".to_string()
}

fn default_log_file_path() -> String {
    "/var/log/aria-agent/aria-agent.log".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ebpf_path: default_ebpf_path(),
            trace_backend: default_trace_backend(),
            trace_auto_allow_ringbuf: default_trace_auto_allow_ringbuf(),
            pin_path: default_pin_path(),
            state_path: default_state_path(),
            iface_pattern: default_iface_pattern(),
            max_port_policies: default_max_port_policies(),
            listen_addr: default_listen_addr(),
            log_format: default_log_format(),
            log_filter: default_log_filter(),
            log_file_path: default_log_file_path(),
        }
    }
}

fn build_env_filter(config: &Config) -> Result<EnvFilter, String> {
    EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .map_err(|e| format!("failed to build log filter: {}", e))
}

#[derive(Clone)]
struct DualMakeWriter {
    file: Option<Arc<Mutex<File>>>,
}

struct DualWriter {
    stdout: io::Stdout,
    file: Option<Arc<Mutex<File>>>,
}

impl<'a> MakeWriter<'a> for DualMakeWriter {
    type Writer = DualWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DualWriter {
            stdout: io::stdout(),
            file: self.file.clone(),
        }
    }
}

impl Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdout.write_all(buf)?;
        if let Some(file) = &self.file {
            let mut file = file
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file mutex poisoned"))?;
            file.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()?;
        if let Some(file) = &self.file {
            let mut file = file
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "log file mutex poisoned"))?;
            file.flush()?;
        }
        Ok(())
    }
}

fn build_log_writer(config: &Config) -> DualMakeWriter {
    let path = config.log_file_path.trim();
    if path.is_empty() {
        return DualMakeWriter { file: None };
    }

    let log_path = PathBuf::from(path);
    let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        eprintln!(
            "Warning: failed to create log directory {:?}: {}; file logging disabled",
            parent, e
        );
        return DualMakeWriter { file: None };
    }

    let file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "Warning: failed to open log file {:?}: {}; file logging disabled",
                log_path, e
            );
            return DualMakeWriter { file: None };
        }
    };

    DualMakeWriter {
        file: Some(Arc::new(Mutex::new(file))),
    }
}

fn init_tracing(config: &Config) -> Result<(), String> {
    match config.log_format.to_ascii_lowercase().as_str() {
        "text" => tracing_subscriber::fmt()
            .compact()
            .with_env_filter(build_env_filter(config)?)
            .with_target(true)
            .with_thread_names(true)
            .with_writer(build_log_writer(config))
            .try_init()
            .map_err(|e| format!("failed to initialize text logger: {}", e)),
        "json" => tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_env_filter(build_env_filter(config)?)
            .with_target(true)
            .with_thread_names(true)
            .with_writer(build_log_writer(config))
            .try_init()
            .map_err(|e| format!("failed to initialize json logger: {}", e)),
        other => Err(format!(
            "unsupported log_format '{}': expected 'text' or 'json'",
            other
        )),
    }
}

fn load_config(path: &PathBuf) -> Config {
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => {
                    println!("Loaded config from {:?}", path);
                    return config;
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse config {:?}: {}", path, e);
                    eprintln!("Using default configuration");
                }
            },
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
    const SSL_RECONCILE_INTERVAL_SECS: u64 = 15;

    // Root privilege check
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: aria-agent must run as root");
        std::process::exit(1);
    }

    let args = Args::parse();
    let config = load_config(&args.config);
    if let Err(e) = init_tracing(&config) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let trace_backend_preference =
        match ebpf_binary::TraceBackendPreference::parse(&config.trace_backend) {
            Ok(preference) => preference,
            Err(e) => {
                error!(trace_backend = %config.trace_backend, error = %e, "invalid trace backend preference");
                std::process::exit(1);
            }
        };

    let resolved_ebpf = match ebpf_binary::resolve_ebpf_binary(
        &config.ebpf_path,
        trace_backend_preference,
        ebpf_binary::TraceBackendResolverOptions {
            allow_auto_ringbuf: config.trace_auto_allow_ringbuf,
        },
    ) {
        Ok(resolved) => resolved,
        Err(e) => {
            error!(requested_ebpf_path = %config.ebpf_path, error = %e, "failed to resolve eBPF binary");
            std::process::exit(1);
        }
    };

    info!(
        config_path = %args.config.display(),
        requested_ebpf_path = %resolved_ebpf.requested_path,
        ebpf_path = %resolved_ebpf.selected_path,
        trace_backend_preference = %config.trace_backend,
        trace_auto_allow_ringbuf = config.trace_auto_allow_ringbuf,
        trace_backend = %resolved_ebpf.trace_backend,
        kernel_version = ?resolved_ebpf.kernel_version,
        pin_path = %config.pin_path,
        state_path = %config.state_path,
        iface_pattern = %config.iface_pattern,
        max_port_policies = config.max_port_policies,
        listen_addr = %config.listen_addr,
        log_format = %config.log_format,
        log_filter = %config.log_filter,
        log_file_path = %config.log_file_path,
        "starting aria-agent"
    );

    // Verify eBPF binary exists
    if !std::path::Path::new(&resolved_ebpf.selected_path).exists() {
        error!(ebpf_path = %resolved_ebpf.selected_path, "eBPF binary not found");
        std::process::exit(1);
    }

    // Create base directories
    if let Err(e) = std::fs::create_dir_all(&config.pin_path) {
        warn!(path = %config.pin_path, error = %e, "failed to create pin directory");
    }
    if let Err(e) = std::fs::create_dir_all(&config.state_path) {
        warn!(path = %config.state_path, error = %e, "failed to create state directory");
    }

    let trace_manager = Arc::new(trace_backend::TraceManager::new(
        resolved_ebpf.trace_backend,
    ));

    let ssl_manager = Arc::new(ssl_manager::SslManager::new(
        &resolved_ebpf.selected_path,
        &config.pin_path,
    ));
    if let Err(e) = ssl_manager.ensure_loaded().await {
        warn!(error = %e, "failed to initialize global SSL manager");
    }
    if let Err(e) = ssl_manager.cleanup_legacy_instance_pins().await {
        warn!(error = %e, "failed to clean legacy SSL pins");
    }

    let kernel_drop_manager = Arc::new(kernel_drop_manager::KernelDropManager::new(
        &resolved_ebpf.selected_path,
        &config.pin_path,
        &config.state_path,
    ));
    if let Err(e) = kernel_drop_manager.ensure_loaded().await {
        warn!(error = %e, "failed to initialize kernel drop manager");
    } else {
        let status = kernel_drop_manager.status_snapshot().await;
        info!(
            loaded = status.loaded,
            mode = ?status.mode,
            managed_ifaces = status.managed_ifaces,
            pin_path = %kernel_drop_manager.pin_path(),
            last_error = ?status.last_error,
            "kernel drop manager ready"
        );
    }

    // Create ControlPlane
    let control_plane = Arc::new(control_plane::ControlPlane::new(
        &resolved_ebpf.selected_path,
        &config.pin_path,
        &config.state_path,
        ssl_manager.clone(),
        kernel_drop_manager.clone(),
        trace_manager,
    ));

    // Note: instances are registered by TapRegistry::attach when XDP is actually attached.
    // Pre-loading state files without XDP would expose stale data via the API.

    let registry = Arc::new(tap_registry::TapRegistry::new(
        &resolved_ebpf.selected_path,
        &config.pin_path,
        &config.state_path,
        &config.iface_pattern,
        config.max_port_policies,
        control_plane.clone(),
    ));

    let router = api_routes::build_router(control_plane.clone());
    let listen_addr = config.listen_addr.clone();
    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(listen_addr = %listen_addr, error = %e, "failed to bind HTTP server");
            std::process::exit(1);
        }
    };

    // Bind before starting background tasks so we fail before any interfaces are attached.
    // Start netlink monitoring
    let registry_clone = registry.clone();
    let netlink_task = tokio::spawn(async move {
        loop {
            if let Err(e) = netlink::monitor(registry_clone.clone()).await {
                warn!(error = %e, "netlink monitor failed; restarting");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    });

    // Start background compact task (WAL → snapshot when threshold reached or periodically)
    let compact_cp = control_plane.clone();
    let compact_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            compact_cp.compact_if_needed().await;
        }
    });

    let ssl_reconcile_cp = control_plane.clone();
    let ssl_reconcile_task = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(SSL_RECONCILE_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            ssl_reconcile_cp.reconcile_ssl_runtime_state().await;
        }
    });

    // Start HTTP server
    let http_task = tokio::spawn(async move {
        info!(listen_addr = %listen_addr, "HTTP API server listening");
        if let Err(e) = axum::serve(listener, router).await {
            error!(error = %e, "HTTP server stopped with error");
        }
    });

    info!("aria-agent running");

    // Wait for shutdown signal
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to create SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to create SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv() => info!("received SIGINT"),
    }

    info!("shutting down aria-agent");

    // Abort tasks
    netlink_task.abort();
    http_task.abort();
    compact_task.abort();
    ssl_reconcile_task.abort();

    // Final compact: ensure WAL is flushed to snapshot
    control_plane.compact_all().await;

    // Graceful shutdown: detach all instances
    registry.shutdown().await;

    info!("aria-agent stopped");
}
