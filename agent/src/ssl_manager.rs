use std::path::Path;

use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::ssl_support::{
    attach_uprobe_if_needed, find_libssl, is_ssl_pin_name, pin_map_if_needed,
    pin_program_if_needed, load_uprobe_program, SSL_LINK_NAMES, SSL_MAP_NAMES,
    SSL_PROGRAM_NAMES, SSL_UPROBE_SPECS,
};

struct SslManagerState {
    loaded: bool,
    libssl_path: Option<String>,
    last_error: Option<String>,
}

pub struct SslManager {
    ebpf_path: String,
    base_pin_path: String,
    pin_path: String,
    state: Mutex<SslManagerState>,
}

impl SslManager {
    pub fn new(ebpf_path: &str, base_pin_path: &str) -> Self {
        Self {
            ebpf_path: ebpf_path.to_string(),
            base_pin_path: base_pin_path.to_string(),
            pin_path: format!("{}/ssl-global", base_pin_path),
            state: Mutex::new(SslManagerState {
                loaded: false,
                libssl_path: None,
                last_error: None,
            }),
        }
    }

    pub fn pin_path(&self) -> &str {
        &self.pin_path
    }

    pub async fn ensure_loaded(&self) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let libssl_path = find_libssl();
        let need_core_init = !state.loaded || !self.core_pins_ready();
        let need_link_init = libssl_path.is_some() && !self.link_pins_ready();

        if !need_core_init && !need_link_init {
            state.libssl_path = libssl_path;
            state.last_error = None;
            return Ok(());
        }

        let result = self.load_impl(libssl_path.clone());
        match result {
            Ok(()) => {
                state.loaded = true;
                state.libssl_path = libssl_path;
                state.last_error = None;
                Ok(())
            }
            Err(e) => {
                state.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    pub async fn cleanup_legacy_instance_pins(&self) -> Result<(), String> {
        let base = Path::new(&self.base_pin_path);
        if !base.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(base)
            .map_err(|e| format!("read ssl pin base {}: {}", self.base_pin_path, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("iterate ssl pin base: {}", e))?;
            if !entry.path().is_dir() {
                continue;
            }

            let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };

            if name == "system" || name == "ssl-global" {
                continue;
            }

            let child_entries = match std::fs::read_dir(entry.path()) {
                Ok(v) => v,
                Err(e) => {
                    warn!(path = ?entry.path(), error = %e, "failed to scan legacy SSL pin directory");
                    continue;
                }
            };

            for child in child_entries {
                let child = match child {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(path = ?entry.path(), error = %e, "failed to inspect legacy SSL pin directory");
                        continue;
                    }
                };

                let Some(file_name) = child.file_name().to_str().map(|s| s.to_string()) else {
                    continue;
                };

                if !is_ssl_pin_name(&file_name) {
                    continue;
                }

                let path = child.path();
                let result = if path.is_dir() {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };

                if let Err(e) = result {
                    warn!(path = ?path, error = %e, "failed to remove legacy SSL pin");
                }
            }
        }

        Ok(())
    }

    fn load_impl(&self, libssl_path: Option<String>) -> Result<(), String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("create ssl-global pin dir {}: {}", self.pin_path, e))?;

        let bpf_bytes = std::fs::read(&self.ebpf_path)
            .map_err(|e| format!("read ebpf: {}", e))?;
        let mut preserved_ssl_enabled = None;
        let mut bpf = match self.load_bpf_with_pins(&bpf_bytes) {
            Ok(bpf) => bpf,
            Err(first_err) => {
                preserved_ssl_enabled = aria_core::ssl_ops::get_ssl_global_config(&self.pin_path).ok();
                warn!(error = %first_err, "failed to reuse pinned SSL state; recreating ssl-global pins");
                self.reset_ssl_global_pins()?;
                self.load_bpf_with_pins(&bpf_bytes).map_err(|retry_err| {
                    format!(
                        "load ssl manager ebpf: {}; retry after ssl-global reset failed: {}",
                        first_err, retry_err
                    )
                })?
            }
        };

        for map_name in SSL_MAP_NAMES {
            pin_map_if_needed(&mut bpf, map_name, &self.pin_path)?;
        }

        if let Some(enabled) = preserved_ssl_enabled {
            if let Err(e) = aria_core::ssl_ops::set_ssl_global_config(&self.pin_path, enabled) {
                warn!(error = %e, "failed to restore SSL global config after pin reset");
            }
        }

        for prog_name in SSL_PROGRAM_NAMES {
            load_uprobe_program(&mut bpf, prog_name)?;
            pin_program_if_needed(&mut bpf, prog_name, &self.pin_path)?;
        }

        if let Some(libssl) = libssl_path {
            for spec in SSL_UPROBE_SPECS {
                attach_uprobe_if_needed(
                    &mut bpf,
                    spec.program_name,
                    &libssl,
                    spec.symbol_name,
                    &self.pin_path,
                )?;
            }
            info!(libssl = %libssl, "SSL uprobes ready");
        } else {
            info!("libssl not found; SSL probes will attach when libssl becomes available");
        }

        Ok(())
    }

    fn load_bpf_with_pins(&self, bpf_bytes: &[u8]) -> Result<aya::Ebpf, String> {
        aya::EbpfLoader::new()
            .map_pin_path(&self.pin_path)
            .load(bpf_bytes)
            .map_err(|e| format!("{:?}", e))
    }

    fn reset_ssl_global_pins(&self) -> Result<(), String> {
        let dir = Path::new(&self.pin_path);
        if !dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("read ssl-global pin dir {}: {}", self.pin_path, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("iterate ssl-global pin dir: {}", e))?;
            let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };

            if !is_ssl_pin_name(&name) {
                continue;
            }

            let path = entry.path();
            let result = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };

            if let Err(e) = result {
                return Err(format!("remove stale ssl-global pin {:?}: {}", path, e));
            }
        }

        Ok(())
    }

    fn core_pins_ready(&self) -> bool {
        SSL_MAP_NAMES.iter().all(|name| Path::new(&format!("{}/{}", self.pin_path, name)).exists())
            && SSL_PROGRAM_NAMES.iter().all(|name| Path::new(&format!("{}/{}", self.pin_path, name)).exists())
    }

    fn link_pins_ready(&self) -> bool {
        SSL_LINK_NAMES
            .iter()
            .all(|name| Path::new(&format!("{}/{}", self.pin_path, name)).exists())
    }
}
