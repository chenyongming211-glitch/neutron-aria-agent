use axum::serve::ListenerExt;
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::EnvFilter;

mod api_handlers;
mod api_routes;
mod acl_runtime_schema;
mod control_plane;
mod ebpf_binary;
mod fault_injection;
mod instance;
mod kernel_drop_manager;
mod kernel_drop_support;
mod netlink;
mod neutron_acl_ip;
mod neutron_api;
mod neutron_wal;
mod openapi;
mod service_chain;
mod ssl_manager;
mod ssl_support;
mod system_manager;
mod tap_registry;
mod trace_backend;
mod xdp_link_health;

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
    #[serde(default)]
    allow_unauthenticated_non_loopback: bool,
    #[serde(default = "default_neutron_socket_path")]
    neutron_socket_path: String,
    #[serde(default = "default_neutron_socket_mode")]
    neutron_socket_mode: u32,
    #[serde(default = "default_neutron_peercred_enforce")]
    neutron_peercred_enforce: bool,
    #[serde(default)]
    neutron_peercred_allowed_uids: Vec<u32>,
    #[serde(default)]
    neutron_peercred_allowed_gids: Vec<u32>,
    #[serde(default = "default_neutron_audit_log_path")]
    neutron_audit_log_path: String,
    #[serde(default = "default_ovs_bridge")]
    ovs_bridge: String,
    #[serde(default = "default_log_format")]
    log_format: String,
    #[serde(default = "default_log_filter")]
    log_filter: String,
    #[serde(default = "default_log_file_path")]
    log_file_path: String,
    #[serde(default)]
    fragment_tracking_field_verified: bool,
    #[serde(default)]
    fragment_tracking: FragmentTrackingConfig,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct FragmentTrackingConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_fragment_context_capacity")]
    max_entries: u32,
    #[serde(default = "default_fragment_timeout_seconds")]
    ipv4_timeout_seconds: u64,
    #[serde(default = "default_fragment_timeout_seconds")]
    ipv6_timeout_seconds: u64,
}

impl Default for FragmentTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entries: default_fragment_context_capacity(),
            ipv4_timeout_seconds: default_fragment_timeout_seconds(),
            ipv6_timeout_seconds: default_fragment_timeout_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FragmentTrackingSettings {
    pub(crate) enabled: bool,
    pub(crate) field_verified: bool,
    pub(crate) max_entries: u32,
    pub(crate) ipv4_timeout_seconds: u64,
    pub(crate) ipv6_timeout_seconds: u64,
}

impl Default for FragmentTrackingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            field_verified: false,
            max_entries: default_fragment_context_capacity(),
            ipv4_timeout_seconds: default_fragment_timeout_seconds(),
            ipv6_timeout_seconds: default_fragment_timeout_seconds(),
        }
    }
}

impl FragmentTrackingSettings {
    pub(crate) fn require_acl_ct_ready(
        self,
        conntrack_enabled: bool,
        acl_enabled: bool,
    ) -> Result<(), String> {
        if (conntrack_enabled || acl_enabled) && self.field_verified && !self.enabled {
            return Err(
                "fragment tracking is explicitly disabled after verified field evidence; ACL/CT activation is blocked"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(crate) fn runtime_config(
        self,
        runtime_mode: u8,
    ) -> Result<aria_core::common::FragmentConfig, String> {
        if runtime_mode != aria_core::common::FRAGMENT_RUNTIME_MODE_MANAGED
            && runtime_mode != aria_core::common::FRAGMENT_RUNTIME_MODE_STANDALONE
        {
            return Err(format!(
                "fragment tracking runtime mode {} is invalid",
                runtime_mode
            ));
        }
        Ok(aria_core::common::FragmentConfig {
            version: aria_core::common::FRAGMENT_CONFIG_VERSION,
            enabled: if self.enabled {
                aria_core::common::FRAGMENT_CONFIG_ENABLED
            } else {
                aria_core::common::FRAGMENT_CONFIG_DISABLED
            },
            runtime_mode,
            _pad: [0; 5],
            ipv4_timeout_ns: self.ipv4_timeout_seconds * 1_000_000_000,
            ipv6_timeout_ns: self.ipv6_timeout_seconds * 1_000_000_000,
        })
    }
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

fn detach_runtime_on_shutdown(mode: AgentMode) -> bool {
    mode == AgentMode::Standalone
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

fn default_fragment_context_capacity() -> u32 {
    8192
}

fn default_fragment_timeout_seconds() -> u64 {
    30
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

fn default_neutron_peercred_enforce() -> bool {
    false
}

fn default_neutron_audit_log_path() -> String {
    "/var/log/aria-agent/neutron-uds-audit.log".to_string()
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
            allow_unauthenticated_non_loopback: false,
            neutron_socket_path: default_neutron_socket_path(),
            neutron_socket_mode: default_neutron_socket_mode(),
            neutron_peercred_enforce: default_neutron_peercred_enforce(),
            neutron_peercred_allowed_uids: Vec::new(),
            neutron_peercred_allowed_gids: Vec::new(),
            neutron_audit_log_path: default_neutron_audit_log_path(),
            ovs_bridge: default_ovs_bridge(),
            log_format: default_log_format(),
            log_filter: default_log_filter(),
            log_file_path: default_log_file_path(),
            fragment_tracking_field_verified: false,
            fragment_tracking: FragmentTrackingConfig::default(),
        }
    }
}

impl Config {
    fn requested_auto_attach(&self) -> bool {
        self.auto_attach
            .unwrap_or(self.mode == AgentMode::Standalone)
    }

    fn effective_auto_attach(&self) -> bool {
        self.mode == AgentMode::Standalone && self.requested_auto_attach()
    }

    fn neutron_socket_enabled(&self) -> bool {
        self.mode == AgentMode::NeutronManaged
    }

    fn management_listen_addr(&self) -> Result<SocketAddr, String> {
        let listen_addr = self.listen_addr.parse::<SocketAddr>().map_err(|_| {
            format!(
                "invalid listen_addr '{}': expected an explicit IP socket such as 127.0.0.1:8080 or [::1]:8080",
                self.listen_addr
            )
        })?;

        if listen_addr.ip().is_loopback() || self.allow_unauthenticated_non_loopback {
            return Ok(listen_addr);
        }

        Err(format!(
            "listen_addr '{}' is not loopback; set allow_unauthenticated_non_loopback = true only when an external security boundary protects the unauthenticated root management API",
            self.listen_addr
        ))
    }

    fn fragment_tracking_settings(&self) -> Result<FragmentTrackingSettings, String> {
        if self.fragment_tracking.max_entries == 0 {
            return Err("fragment_tracking.max_entries must be positive".to_string());
        }
        for (field, value) in [
            (
                "fragment_tracking.ipv4_timeout_seconds",
                self.fragment_tracking.ipv4_timeout_seconds,
            ),
            (
                "fragment_tracking.ipv6_timeout_seconds",
                self.fragment_tracking.ipv6_timeout_seconds,
            ),
        ] {
            if !(1..=60).contains(&value) {
                return Err(format!("{} must be in 1..=60", field));
            }
        }
        if self.fragment_tracking.enabled && !self.fragment_tracking_field_verified {
            return Err(
                "fragment tracking activation requires verified field evidence".to_string(),
            );
        }
        Ok(FragmentTrackingSettings {
            enabled: self.fragment_tracking.enabled,
            field_verified: self.fragment_tracking_field_verified,
            max_entries: self.fragment_tracking.max_entries,
            ipv4_timeout_seconds: self.fragment_tracking.ipv4_timeout_seconds,
            ipv6_timeout_seconds: self.fragment_tracking.ipv6_timeout_seconds,
        })
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

    let file = match OpenOptions::new().create(true).append(true).open(&log_path) {
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

struct StartupConfig {
    config: Config,
    iface_pattern: Regex,
}

fn load_startup_config(path: &Path) -> Result<StartupConfig, String> {
    let config = match std::fs::read_to_string(path) {
        Ok(contents) => {
            let config = toml::from_str(&contents).map_err(|error| {
                format!(
                    "failed to parse configuration {}: {}",
                    path.display(),
                    error
                )
            })?;
            println!("Loaded config from {:?}", path);
            config
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("Config file {:?} not found, using defaults", path);
            Config::default()
        }
        Err(error) => {
            return Err(format!(
                "failed to read configuration {}: {}",
                path.display(),
                error
            ));
        }
    };

    let iface_pattern = Regex::new(&config.iface_pattern).map_err(|error| {
        format!(
            "invalid iface_pattern {:?}: {}",
            config.iface_pattern, error
        )
    })?;

    Ok(StartupConfig {
        config,
        iface_pattern,
    })
}

async fn bind_neutron_socket(path: &str, mode: u32) -> Result<tokio::net::UnixListener, String> {
    if mode & !0o777 != 0 {
        return Err(format!(
            "invalid neutron socket mode {:o}; expected permission bits <= 0777",
            mode
        ));
    }
    if mode & 0o007 != 0 {
        return Err(format!(
            "invalid neutron socket mode {:o}; other-user permissions are not allowed",
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
    align_neutron_socket_group(socket_path)?;
    Ok(listener)
}

fn align_neutron_socket_group(socket_path: &Path) -> Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Ok(());
    };
    let parent_gid = std::fs::metadata(parent)
        .map_err(|e| {
            format!(
                "failed to stat neutron socket directory {}: {}",
                parent.display(),
                e
            )
        })?
        .gid();
    let socket_gid = std::fs::metadata(socket_path)
        .map_err(|e| {
            format!(
                "failed to stat neutron socket {}: {}",
                socket_path.display(),
                e
            )
        })?
        .gid();
    if socket_gid == parent_gid {
        return Ok(());
    }

    let c_path = CString::new(socket_path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "failed to chgrp neutron socket {}; path contains NUL",
            socket_path.display()
        )
    })?;
    let rc = unsafe {
        libc::chown(
            c_path.as_ptr(),
            -1i32 as libc::uid_t,
            parent_gid as libc::gid_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "failed to chgrp neutron socket {} to gid {}: {}",
            socket_path.display(),
            parent_gid,
            io::Error::last_os_error()
        ));
    }
    info!(
        socket_path = %socket_path.display(),
        socket_gid = parent_gid,
        "aligned Neutron UDS socket group with parent directory"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnixPeerCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerAuthDecision {
    allowed: bool,
    reason: &'static str,
}

#[derive(Clone, Debug)]
struct NeutronPeerAuth {
    enforce: bool,
    allowed_uids: Vec<u32>,
    allowed_gids: Vec<u32>,
    audit_log_path: Option<PathBuf>,
}

impl NeutronPeerAuth {
    fn from_config(config: &Config) -> Result<Self, String> {
        if config.neutron_socket_enabled()
            && config.neutron_peercred_enforce
            && config.neutron_peercred_allowed_uids.is_empty()
            && config.neutron_peercred_allowed_gids.is_empty()
        {
            return Err(
                "neutron_peercred_enforce=true requires neutron_peercred_allowed_uids or neutron_peercred_allowed_gids"
                    .to_string(),
            );
        }

        let audit_log_path = config.neutron_audit_log_path.trim();
        let audit_log_path = if audit_log_path.is_empty() {
            None
        } else {
            Some(PathBuf::from(audit_log_path))
        };

        Ok(Self {
            enforce: config.neutron_peercred_enforce,
            allowed_uids: config.neutron_peercred_allowed_uids.clone(),
            allowed_gids: config.neutron_peercred_allowed_gids.clone(),
            audit_log_path,
        })
    }

    fn authorize(&self, cred: Option<UnixPeerCred>) -> PeerAuthDecision {
        if !self.enforce {
            return PeerAuthDecision {
                allowed: true,
                reason: "peercred_audit_only",
            };
        }

        let Some(cred) = cred else {
            return PeerAuthDecision {
                allowed: false,
                reason: "UDS_PEERCRED_UNAVAILABLE",
            };
        };

        if self.allowed_uids.contains(&cred.uid) || self.allowed_gids.contains(&cred.gid) {
            PeerAuthDecision {
                allowed: true,
                reason: "peercred_allow_list_match",
            }
        } else {
            PeerAuthDecision {
                allowed: false,
                reason: "UDS_PEER_UNAUTHORIZED",
            }
        }
    }

    fn audit_and_enforce(&self, stream: &mut tokio::net::UnixStream) {
        let (cred, credential_error) = match read_peercred(stream) {
            Ok(cred) => (Some(cred), None),
            Err(e) => (None, Some(e)),
        };
        let decision = self.authorize(cred);
        self.write_audit(cred, decision, credential_error.as_deref());

        match (decision.allowed, cred) {
            (true, Some(cred)) => info!(
                peer_pid = cred.pid,
                peer_uid = cred.uid,
                peer_gid = cred.gid,
                peer_auth_reason = decision.reason,
                "accepted Neutron UDS peer"
            ),
            (true, None) => info!(
                peer_auth_reason = decision.reason,
                credential_error = credential_error.as_deref().unwrap_or("unknown"),
                "accepted Neutron UDS peer without credentials"
            ),
            (false, Some(cred)) => warn!(
                peer_pid = cred.pid,
                peer_uid = cred.uid,
                peer_gid = cred.gid,
                peer_auth_reason = decision.reason,
                "rejected Neutron UDS peer"
            ),
            (false, None) => warn!(
                peer_auth_reason = decision.reason,
                credential_error = credential_error.as_deref().unwrap_or("unknown"),
                "rejected Neutron UDS peer without credentials"
            ),
        }

        if !decision.allowed {
            // Deny before request parsing. Route-level JSON errors can be added later
            // if operators need them, but the v0.9 gate is connection hardening.
            let rc = unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_RDWR) };
            if rc != 0 {
                warn!(
                    error = %io::Error::last_os_error(),
                    "failed to shutdown unauthorized Neutron UDS peer"
                );
            }
        }
    }

    fn write_audit(
        &self,
        cred: Option<UnixPeerCred>,
        decision: PeerAuthDecision,
        credential_error: Option<&str>,
    ) {
        let Some(path) = &self.audit_log_path else {
            return;
        };

        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(path = %path.display(), error = %e, "failed to create Neutron UDS audit directory");
                return;
            }
        }

        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();
        let line = serde_json::json!({
            "ts_ms": ts_ms,
            "event": "neutron_uds_peer_auth",
            "enforce": self.enforce,
            "result": if decision.allowed { "allowed" } else { "denied" },
            "reason": decision.reason,
            "peer_pid": cred.map(|value| value.pid),
            "peer_uid": cred.map(|value| value.uid),
            "peer_gid": cred.map(|value| value.gid),
            "credential_error": credential_error,
        });

        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", line) {
                    warn!(path = %path.display(), error = %e, "failed to write Neutron UDS audit line");
                }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to open Neutron UDS audit log")
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn read_peercred(stream: &tokio::net::UnixStream) -> Result<UnixPeerCred, String> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "getsockopt(SO_PEERCRED) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let cred = unsafe { cred.assume_init() };
    Ok(UnixPeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_peercred(_stream: &tokio::net::UnixStream) -> Result<UnixPeerCred, String> {
    Err("SO_PEERCRED is not supported on this platform".to_string())
}

#[tokio::main]
async fn main() {
    const SSL_RECONCILE_INTERVAL_SECS: u64 = 15;
    const TC_ACL_HEALTH_INTERVAL_SECS: u64 = 10;

    // Root privilege check
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: aria-agent must run as root");
        std::process::exit(1);
    }

    let args = Args::parse();
    let StartupConfig {
        config,
        iface_pattern,
    } = match load_startup_config(&args.config) {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("Error: invalid startup configuration: {}", error);
            std::process::exit(1);
        }
    };
    let fragment_tracking = match config.fragment_tracking_settings() {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("Error: invalid fragment tracking configuration: {}", e);
            std::process::exit(1);
        }
    };
    let management_listen_addr = match config.management_listen_addr() {
        Ok(listen_addr) => listen_addr,
        Err(e) => {
            eprintln!(
                "Error: invalid management API listener configuration: {}",
                e
            );
            std::process::exit(1);
        }
    };
    if let Err(e) = init_tracing(&config) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    if !management_listen_addr.ip().is_loopback() {
        warn!(
            listen_addr = %management_listen_addr,
            allow_unauthenticated_non_loopback = config.allow_unauthenticated_non_loopback,
            "unauthenticated root HTTP management API exposed on non-loopback address"
        );
    }
    if config.mode == AgentMode::NeutronManaged && config.requested_auto_attach() {
        warn!(
            mode = config.mode.as_str(),
            "auto_attach=true is ignored in neutron_managed mode; snapshot authority is required"
        );
    }
    let neutron_peer_auth = match NeutronPeerAuth::from_config(&config) {
        Ok(policy) => policy,
        Err(e) => {
            error!(error = %e, "invalid Neutron UDS peer authentication config");
            std::process::exit(1);
        }
    };

    let trace_backend_preference = match ebpf_binary::TraceBackendPreference::parse(
        &config.trace_backend,
    ) {
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
        listen_addr = %management_listen_addr,
        allow_unauthenticated_non_loopback = config.allow_unauthenticated_non_loopback,
        neutron_socket_path = %config.neutron_socket_path,
        neutron_socket_mode = format_args!("{:o}", config.neutron_socket_mode),
        neutron_peercred_enforce = config.neutron_peercred_enforce,
        neutron_peercred_allowed_uids = ?config.neutron_peercred_allowed_uids,
        neutron_peercred_allowed_gids = ?config.neutron_peercred_allowed_gids,
        neutron_audit_log_path = %config.neutron_audit_log_path,
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
    let control_plane = Arc::new(control_plane::ControlPlane::new_with_fragment_tracking(
        &resolved_ebpf.selected_path,
        &config.pin_path,
        &config.state_path,
        ssl_manager.clone(),
        kernel_drop_manager.clone(),
        trace_manager,
        fragment_tracking,
    ));

    // Note: instances are registered by TapRegistry::attach when XDP is actually attached.
    // Pre-loading state files without XDP would expose stale data via the API.

    let registry = Arc::new(tap_registry::TapRegistry::new(
        &resolved_ebpf.selected_path,
        &config.pin_path,
        &config.state_path,
        iface_pattern,
        config.max_port_policies,
        control_plane.clone(),
    ));

    let router = api_routes::build_router(control_plane.clone());
    let listen_addr = management_listen_addr;
    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
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

    let tc_health_cp = control_plane.clone();
    let tc_acl_health_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            TC_ACL_HEALTH_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = tc_health_cp.reconcile_tc_acl_health().await;
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

    let neutron_runtime = neutron_listener.map(|listener| {
        let runtime = neutron_api::build_router(
            registry.clone(),
            control_plane.clone(),
            config.ovs_bridge.clone(),
        );
        let router = runtime.router;
        let background = runtime.background;
        let neutron_peer_auth = neutron_peer_auth.clone();
        let server = tokio::spawn(async move {
            info!(socket_path = %neutron_socket_path, "Neutron UDS API server listening");
            let listener = listener.tap_io(move |stream: &mut tokio::net::UnixStream| {
                neutron_peer_auth.audit_and_enforce(stream);
            });
            if let Err(e) = axum::serve(listener, router).await {
                error!(error = %e, "Neutron UDS API server stopped with error");
            }
        });
        (server, background)
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
    if let Some((server, background)) = neutron_runtime {
        server.abort();
        background.abort().await;
    }
    compact_task.abort();
    tc_acl_health_task.abort();
    ssl_reconcile_task.abort();

    // Final compact: ensure WAL is flushed to snapshot
    control_plane.compact_all().await;

    if detach_runtime_on_shutdown(config.mode) {
        registry.shutdown().await;
    } else {
        info!(
            mode = config.mode.as_str(),
            "preserving Neutron-managed kernel runtime across agent shutdown"
        );
    }

    info!("aria-agent stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup_config_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aria-startup-config-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    fn startup_config_error(path: &Path) -> String {
        match load_startup_config(path) {
            Ok(_) => panic!("invalid startup configuration must not use defaults"),
            Err(error) => error,
        }
    }

    fn management_listener_config(listen_addr: &str, allow_non_loopback: bool) -> Config {
        toml::from_str(&format!(
            "listen_addr = {:?}\nallow_unauthenticated_non_loopback = {}\n",
            listen_addr, allow_non_loopback
        ))
        .unwrap()
    }

    #[test]
    fn management_listener_default_is_loopback_and_unsafe_override_is_off() {
        let config = Config::default();

        assert!(!config.allow_unauthenticated_non_loopback);
        assert_eq!(
            config.management_listen_addr().unwrap(),
            "127.0.0.1:8080"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        );
    }

    #[test]
    fn management_listener_accepts_explicit_ipv4_and_ipv6_loopback() {
        for value in ["127.4.3.2:8080", "[::1]:8080"] {
            let config = management_listener_config(value, false);
            assert_eq!(
                config.management_listen_addr().unwrap(),
                value.parse::<std::net::SocketAddr>().unwrap()
            );
        }
    }

    #[test]
    fn management_listener_rejects_non_loopback_without_explicit_override() {
        for value in [
            "0.0.0.0:8080",
            "[::]:8080",
            "10.0.0.8:8080",
            "198.51.100.8:8080",
            "[fe80::1]:8080",
            "[ff02::1]:8080",
            "[::ffff:127.0.0.1]:8080",
        ] {
            let error = management_listener_config(value, false)
                .management_listen_addr()
                .unwrap_err();
            assert!(error.contains(value));
            assert!(error.contains("allow_unauthenticated_non_loopback = true"));
        }
    }

    #[test]
    fn management_listener_rejects_hostname_and_malformed_values_without_resolution() {
        for value in ["localhost:8080", "127.0.0.1", "not-an-address"] {
            let error = management_listener_config(value, false)
                .management_listen_addr()
                .unwrap_err();
            assert!(error.contains(value));
            assert!(error.contains("explicit IP socket"));
        }
    }

    #[test]
    fn management_listener_explicit_override_allows_only_valid_non_loopback_socket() {
        let config = management_listener_config("192.0.2.20:8080", true);
        assert!(config.allow_unauthenticated_non_loopback);
        assert_eq!(
            config.management_listen_addr().unwrap(),
            "192.0.2.20:8080"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        );

        let error = management_listener_config("external.example:8080", true)
            .management_listen_addr()
            .unwrap_err();
        assert!(error.contains("explicit IP socket"));
    }

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
        assert!(!config.neutron_peercred_enforce);
    }

    #[test]
    fn startup_config_missing_path_uses_documented_defaults() {
        let path = startup_config_path("missing");
        let startup = load_startup_config(&path).unwrap();

        assert_eq!(startup.config.mode, AgentMode::Standalone);
        assert!(startup.config.effective_auto_attach());
        assert!(startup.iface_pattern.is_match("tap123"));
        assert!(!startup.iface_pattern.is_match("qvo123"));
    }

    #[test]
    fn startup_config_valid_neutron_mode_and_custom_pattern_are_preserved() {
        let path = startup_config_path("valid-neutron");
        std::fs::write(
            &path,
            "mode = \"neutron_managed\"\niface_pattern = \"^qvo[0-9]+$\"\n",
        )
        .unwrap();

        let startup = load_startup_config(&path).unwrap();
        assert_eq!(startup.config.mode, AgentMode::NeutronManaged);
        assert!(!startup.config.effective_auto_attach());
        assert!(startup.iface_pattern.is_match("qvo12"));
        assert!(!startup.iface_pattern.is_match("tap12"));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_config_valid_standalone_disable_and_custom_pattern_are_preserved() {
        let path = startup_config_path("valid-standalone");
        std::fs::write(
            &path,
            "mode = \"standalone\"\nauto_attach = false\niface_pattern = \"^br-[a-z]+$\"\n",
        )
        .unwrap();

        let startup = load_startup_config(&path).unwrap();
        assert_eq!(startup.config.mode, AgentMode::Standalone);
        assert!(!startup.config.effective_auto_attach());
        assert!(startup.iface_pattern.is_match("br-edge"));
        assert!(!startup.iface_pattern.is_match("tap12"));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_config_malformed_toml_is_fatal() {
        let path = startup_config_path("malformed");
        std::fs::write(&path, "mode = [\n").unwrap();

        let error = startup_config_error(&path);
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("parse configuration"));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_config_existing_unreadable_path_is_fatal() {
        let path = startup_config_path("unreadable");
        std::fs::create_dir(&path).unwrap();

        let error = startup_config_error(&path);
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("read configuration"));

        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn startup_config_invalid_iface_pattern_is_fatal() {
        let path = startup_config_path("invalid-pattern");
        std::fs::write(&path, "iface_pattern = \"[\"\n").unwrap();

        let error = startup_config_error(&path);
        assert!(error.contains("iface_pattern"));
        assert!(error.contains("["));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn neutron_managed_shutdown_preserves_kernel_runtime() {
        assert!(!detach_runtime_on_shutdown(AgentMode::NeutronManaged));
        assert!(detach_runtime_on_shutdown(AgentMode::Standalone));
    }

    #[test]
    fn startup_config_accepts_neutron_socket_and_peercred_settings() {
        let config: Config = toml::from_str(
            r#"
mode = "neutron_managed"
neutron_socket_mode = 432
neutron_peercred_enforce = true
neutron_peercred_allowed_uids = [0, 4242]
neutron_peercred_allowed_gids = [4243]
neutron_audit_log_path = "/tmp/aria-neutron-uds-audit.log"
"#,
        )
        .unwrap();

        assert_eq!(config.neutron_socket_mode, 0o660);
        assert!(config.neutron_peercred_enforce);
        assert_eq!(config.neutron_peercred_allowed_uids, vec![0, 4242]);
        assert_eq!(config.neutron_peercred_allowed_gids, vec![4243]);
        assert_eq!(
            config.neutron_audit_log_path,
            "/tmp/aria-neutron-uds-audit.log"
        );
    }

    #[tokio::test]
    async fn neutron_socket_group_tracks_parent_directory() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aria-agent-neutron-socket-{}-{}",
            std::process::id(),
            suffix
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("aria-agent.sock");

        let listener = bind_neutron_socket(socket.to_str().unwrap(), 0o660)
            .await
            .unwrap();

        let socket_meta = std::fs::metadata(&socket).unwrap();
        let parent_meta = std::fs::metadata(&dir).unwrap();
        assert!(socket_meta.file_type().is_socket());
        assert_eq!(socket_meta.permissions().mode() & 0o777, 0o660);
        assert_eq!(socket_meta.gid(), parent_meta.gid());

        drop(listener);
        std::fs::remove_file(&socket).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn peercred_policy_requires_allow_list_when_enforced() {
        let config: Config = toml::from_str(
            r#"
mode = "neutron_managed"
neutron_peercred_enforce = true
"#,
        )
        .unwrap();

        let error = NeutronPeerAuth::from_config(&config).unwrap_err();
        assert!(error.contains("requires neutron_peercred_allowed_uids"));
    }

    #[test]
    fn peercred_policy_allows_configured_uid_or_gid() {
        let config: Config = toml::from_str(
            r#"
mode = "neutron_managed"
neutron_peercred_enforce = true
neutron_peercred_allowed_uids = [1001]
neutron_peercred_allowed_gids = [1002]
"#,
        )
        .unwrap();
        let policy = NeutronPeerAuth::from_config(&config).unwrap();

        assert!(
            policy
                .authorize(Some(UnixPeerCred {
                    pid: 10,
                    uid: 1001,
                    gid: 1,
                }))
                .allowed
        );
        assert!(
            policy
                .authorize(Some(UnixPeerCred {
                    pid: 11,
                    uid: 1,
                    gid: 1002,
                }))
                .allowed
        );
        let denied = policy.authorize(Some(UnixPeerCred {
            pid: 12,
            uid: 1,
            gid: 2,
        }));
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "UDS_PEER_UNAUTHORIZED");

        let missing = policy.authorize(None);
        assert!(!missing.allowed);
        assert_eq!(missing.reason, "UDS_PEERCRED_UNAVAILABLE");
    }

    #[test]
    fn peercred_policy_audit_only_allows_without_credentials() {
        let policy = NeutronPeerAuth::from_config(&Config::default()).unwrap();
        let decision = policy.authorize(None);

        assert!(decision.allowed);
        assert_eq!(decision.reason, "peercred_audit_only");
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

    #[test]
    fn fragment_loader_config_defaults_are_safe_and_exact() {
        let settings = Config::default().fragment_tracking_settings().unwrap();

        assert!(!settings.enabled);
        assert!(!settings.field_verified);
        assert_eq!(settings.max_entries, 8192);
        assert_eq!(settings.ipv4_timeout_seconds, 30);
        assert_eq!(settings.ipv6_timeout_seconds, 30);
    }

    #[test]
    fn fragment_loader_config_rejects_zero_capacity() {
        let config: Config = toml::from_str(
            r#"
[fragment_tracking]
max_entries = 0
"#,
        )
        .unwrap();

        let error = config.fragment_tracking_settings().unwrap_err();
        assert!(error.contains("max_entries"));
        assert!(error.contains("positive"));
    }

    #[test]
    fn fragment_loader_config_rejects_timeouts_outside_one_to_sixty_seconds() {
        for (field, value) in [
            ("ipv4_timeout_seconds", 0),
            ("ipv4_timeout_seconds", 61),
            ("ipv6_timeout_seconds", 0),
            ("ipv6_timeout_seconds", 61),
        ] {
            let config: Config = toml::from_str(&format!(
                "[fragment_tracking]\n{field} = {value}\n"
            ))
            .unwrap();

            let error = config.fragment_tracking_settings().unwrap_err();
            assert!(error.contains(field));
            assert!(error.contains("1..=60"));
        }
    }

    #[test]
    fn fragment_loader_config_field_verified_requires_tracking_for_acl_or_ct() {
        let config: Config = toml::from_str(
            r#"
fragment_tracking_field_verified = true

[fragment_tracking]
enabled = false
"#,
        )
        .unwrap();
        let settings = config.fragment_tracking_settings().unwrap();

        settings.require_acl_ct_ready(false, false).unwrap();
        for (conntrack, acl) in [(true, false), (false, true), (true, true)] {
            let error = settings
                .require_acl_ct_ready(conntrack, acl)
                .unwrap_err();
            assert!(error.contains("fragment tracking"));
            assert!(error.contains("field evidence"));
        }
    }

    #[test]
    fn fragment_loader_config_unverified_disabled_default_preserves_existing_acl_forwarding() {
        let settings = Config::default().fragment_tracking_settings().unwrap();

        for (conntrack, acl) in [(true, false), (false, true), (true, true)] {
            settings.require_acl_ct_ready(conntrack, acl).unwrap();
        }
    }

    #[test]
    fn fragment_loader_config_rejects_unverified_activation() {
        let config: Config = toml::from_str(
            r#"
[fragment_tracking]
enabled = true
"#,
        )
        .unwrap();

        let error = config.fragment_tracking_settings().unwrap_err();
        assert!(error.contains("field evidence"));
    }

    #[test]
    fn fragment_loader_config_builds_exact_mode_specific_runtime_contracts() {
        let config: Config = toml::from_str(
            r#"
fragment_tracking_field_verified = true

[fragment_tracking]
enabled = true
max_entries = 4096
ipv4_timeout_seconds = 17
ipv6_timeout_seconds = 43
"#,
        )
        .unwrap();
        let settings = config.fragment_tracking_settings().unwrap();

        for mode in [
            aria_core::common::FRAGMENT_RUNTIME_MODE_MANAGED,
            aria_core::common::FRAGMENT_RUNTIME_MODE_STANDALONE,
        ] {
            let expected = settings.runtime_config(mode).unwrap();
            assert_eq!(expected.version, aria_core::common::FRAGMENT_CONFIG_VERSION);
            assert_eq!(expected.enabled, aria_core::common::FRAGMENT_CONFIG_ENABLED);
            assert_eq!(expected.runtime_mode, mode);
            assert_eq!(expected._pad, [0; 5]);
            assert_eq!(expected.ipv4_timeout_ns, 17_000_000_000);
            assert_eq!(expected.ipv6_timeout_ns, 43_000_000_000);
        }
        assert!(settings.runtime_config(0xff).is_err());
    }

    #[test]
    fn fragment_loader_config_runtime_reuse_requires_exact_config_and_capacity() {
        let settings = Config::default().fragment_tracking_settings().unwrap();
        let expected = settings
            .runtime_config(aria_core::common::FRAGMENT_RUNTIME_MODE_MANAGED)
            .unwrap();

        aria_core::ebpf_ops::validate_fragment_runtime_expectation(
            &expected,
            &expected,
            8192,
            8192,
            settings.max_entries,
        )
        .unwrap();

        let mut wrong_timeout = expected;
        wrong_timeout.ipv4_timeout_ns += 1_000_000_000;
        assert!(aria_core::ebpf_ops::validate_fragment_runtime_expectation(
            &wrong_timeout,
            &expected,
            8192,
            8192,
            settings.max_entries,
        )
        .unwrap_err()
        .contains("config"));

        assert!(aria_core::ebpf_ops::validate_fragment_runtime_expectation(
            &expected,
            &expected,
            4096,
            8192,
            settings.max_entries,
        )
        .unwrap_err()
        .contains("FRAG_CONTEXT_V4"));
    }
}
