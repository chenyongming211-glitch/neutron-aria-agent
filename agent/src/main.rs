use clap::Parser;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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
mod neutron_api;
mod neutron_wal;
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
    #[serde(default = "default_mode")]
    mode: AgentMode,
    #[serde(default)]
    auto_attach: Option<bool>,
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
    #[serde(default = "default_neutron_socket_path")]
    neutron_socket_path: String,
    #[serde(default = "default_neutron_socket_mode")]
    neutron_socket_mode: u32,
    #[serde(default = "default_ovs_bridge")]
    ovs_bridge: String,
    #[serde(default = "default_log_format")]
    log_format: String,
    #[serde(default = "default_log_filter")]
    log_filter: String,
    #[serde(default = "default_log_file_path")]
    log_file_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AgentMode {
    Standalone,
    NeutronManaged,
}

impl AgentMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::NeutronManaged => "neutron_managed",
        }
    }
}

fn default_mode() -> AgentMode {
    AgentMode::Standalone
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

fn default_neutron_socket_path() -> String {
    "/run/aria/aria-agent.sock".to_string()
}

fn default_neutron_socket_mode() -> u32 {
    0o660
}

fn default_ovs_bridge() -> String {
    "br-int".to_string()
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
            mode: default_mode(),
            auto_attach: None,
            ebpf_path: default_ebpf_path(),
            trace_backend: default_trace_backend(),
            trace_auto_allow_ringbuf: default_trace_auto_allow_ringbuf(),
            pin_path: default_pin_path(),
            state_path: default_state_path(),
            iface_pattern: default_iface_pattern(),
            max_port_policies: default_max_port_policies(),
            listen_addr: default_listen_addr(),
            neutron_socket_path: default_neutron_socket_path(),
            neutron_socket_mode: default_neutron_socket_mode(),
            ovs_bridge: default_ovs_bridge(),
            log_format: default_log_format(),
            log_filter: default_log_filter(),
            log_file_path: default_log_file_path(),
        }
    }
}

impl Config {
    fn requested_auto_attach(&self) -> bool {
        self.auto_attach.unwrap_or(self.mode == AgentMode::Standalone)
    }

    fn effective_auto_attach(&self) -> bool {
        self.mode == AgentMode::Standalone && self.requested_auto_attach()
    }

    fn neutron_socket_enabled(&self) -> bool {
        self.mode == AgentMode::NeutronManaged
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

async fn bind_neutron_socket(path: &str, mode: u32) -> Result<tokio::net::UnixListener, String> {
    if mode & !0o777 != 0 {
        return Err(format!(
            "invalid neutron socket mode {:o}; expected permission bits <= 0777",
            mode
        ));
    }

    let socket_path = Path::new(path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create neutron socket directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    if socket_path.exists() {
        let file_type = std::fs::metadata(socket_path)
            .map_err(|e| format!("failed to stat neutron socket {}: {}", path, e))?
            .file_type();
        if !file_type.is_socket() {
            return Err(format!(
                "refusing to remove non-socket neutron API path {}",
                path
            ));
        }
        std::fs::remove_file(socket_path)
            .map_err(|e| format!("failed to remove stale neutron socket {}: {}", path, e))?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path)
        .map_err(|e| format!("failed to bind neutron socket {}: {}", path, e))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("failed to chmod neutron socket {}: {}", path, e))?;
    Ok(listener)
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
    if config.mode == AgentMode::NeutronManaged && config.requested_auto_attach() {
        warn!(
            mode = config.mode.as_str(),
            "auto_attach=true is ignored in neutron_managed mode; snapshot authority is required"
        );
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
        mode = %config.mode.as_str(),
        requested_auto_attach = config.requested_auto_attach(),
        effective_auto_attach = config.effective_auto_attach(),
        pin_path = %config.pin_path,
        state_path = %config.state_path,
        iface_pattern = %config.iface_pattern,
        max_port_policies = config.max_port_policies,
        listen_addr = %config.listen_addr,
        neutron_socket_path = %config.neutron_socket_path,
        neutron_socket_mode = format_args!("{:o}", config.neutron_socket_mode),
        ovs_bridge = %config.ovs_bridge,
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

    let neutron_socket_path = config.neutron_socket_path.clone();
    let neutron_listener = if config.neutron_socket_enabled() {
        match bind_neutron_socket(&neutron_socket_path, config.neutron_socket_mode).await {
            Ok(listener) => Some(listener),
            Err(e) => {
                error!(error = %e, "failed to bind Neutron UDS API");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Bind before starting background tasks so we fail before any interfaces are attached.
    let netlink_task = if config.effective_auto_attach() {
        let registry_clone = registry.clone();
        Some(tokio::spawn(async move {
            loop {
                if let Err(e) = netlink::monitor(registry_clone.clone()).await {
                    warn!(error = %e, "netlink monitor failed; restarting");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }))
    } else {
        info!(
            mode = config.mode.as_str(),
            requested_auto_attach = config.requested_auto_attach(),
            "auto attach disabled; netlink tap monitor not started"
        );
        None
    };

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

    let neutron_task = neutron_listener.map(|listener| {
        let router = neutron_api::build_router(
            registry.clone(),
            control_plane.clone(),
            config.ovs_bridge.clone(),
        );
        tokio::spawn(async move {
            info!(socket_path = %neutron_socket_path, "Neutron UDS API server listening");
            if let Err(e) = axum::serve(listener, router).await {
                error!(error = %e, "Neutron UDS API server stopped with error");
            }
        })
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
    if let Some(task) = netlink_task {
        task.abort();
    }
    http_task.abort();
    if let Some(task) = neutron_task {
        task.abort();
    }
    compact_task.abort();
    ssl_reconcile_task.abort();

    // Final compact: ensure WAL is flushed to snapshot
    control_plane.compact_all().await;

    // Graceful shutdown: detach all instances
    registry.shutdown().await;

    info!("aria-agent stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_mode_defaults_to_standalone_auto_attach() {
        let config = Config::default();

        assert_eq!(config.mode, AgentMode::Standalone);
        assert!(config.requested_auto_attach());
        assert!(config.effective_auto_attach());
    }

    #[test]
    fn startup_mode_neutron_managed_disables_auto_attach_by_default() {
        let config: Config = toml::from_str(r#"mode = "neutron_managed""#).unwrap();

        assert_eq!(config.mode, AgentMode::NeutronManaged);
        assert!(!config.requested_auto_attach());
        assert!(!config.effective_auto_attach());
        assert!(config.neutron_socket_enabled());
        assert_eq!(config.neutron_socket_mode, 0o660);
    }

    #[test]
    fn startup_config_accepts_neutron_socket_mode() {
        let config: Config = toml::from_str(
            r#"
mode = "neutron_managed"
neutron_socket_mode = 438
"#,
        )
        .unwrap();

        assert_eq!(config.neutron_socket_mode, 0o666);
    }

    #[test]
    fn startup_mode_neutron_managed_ignores_explicit_auto_attach_true() {
        let config: Config = toml::from_str(
            r#"
mode = "neutron_managed"
auto_attach = true
"#,
        )
        .unwrap();

        assert!(config.requested_auto_attach());
        assert!(!config.effective_auto_attach());
    }

    #[test]
    fn startup_mode_standalone_can_disable_auto_attach() {
        let config: Config = toml::from_str(r#"auto_attach = false"#).unwrap();

        assert_eq!(config.mode, AgentMode::Standalone);
        assert!(!config.requested_auto_attach());
        assert!(!config.effective_auto_attach());
    }
}
