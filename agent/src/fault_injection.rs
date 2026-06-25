use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::warn;

static MATCHED_HITS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
enum FaultAction {
    Abort,
    Sigkill,
    ReturnError,
    SleepMs(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultConfig {
    point: String,
    after_hits: u64,
    action: FaultAction,
    once_file: Option<String>,
}

impl FaultConfig {
    fn from_env() -> Option<Self> {
        let enabled = env::var("ARIA_ENABLE_FAULT_INJECTION").ok()?;
        if !matches!(enabled.as_str(), "1" | "true" | "TRUE" | "yes" | "YES") {
            return None;
        }

        let point = env::var("ARIA_FAULT_POINT").ok()?;
        if point.trim().is_empty() {
            return None;
        }

        let after_hits = env::var("ARIA_FAULT_AFTER_HITS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);

        let action_name = env::var("ARIA_FAULT_ACTION")
            .unwrap_or_else(|_| "abort".to_string())
            .to_ascii_lowercase();
        let action = match action_name.as_str() {
            "abort" => FaultAction::Abort,
            "sigkill" => FaultAction::Sigkill,
            "return_error" => FaultAction::ReturnError,
            "sleep_ms" => {
                let ms = env::var("ARIA_FAULT_SLEEP_MS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(1000);
                FaultAction::SleepMs(ms)
            }
            _ => FaultAction::ReturnError,
        };
        let once_file = env::var("ARIA_FAULT_ONCE_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Some(Self {
            point,
            after_hits,
            action,
            once_file,
        })
    }

    fn matches(&self, point: &str) -> bool {
        self.point == point || self.point == "*"
    }
}

pub(crate) async fn check(point: &str) -> Result<(), String> {
    let Some(config) = FaultConfig::from_env() else {
        return Ok(());
    };
    if !config.matches(point) {
        return Ok(());
    }

    let hit = MATCHED_HITS.fetch_add(1, Ordering::SeqCst) + 1;
    if hit < config.after_hits {
        return Ok(());
    }
    if let Some(path) = config.once_file.as_deref() {
        match mark_once(path, point, hit) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(());
            }
            Err(e) => {
                return Err(format!("fault once marker write failed at {}: {}", path, e));
            }
        }
    }

    warn!(
        point = %point,
        hit = hit,
        after_hits = config.after_hits,
        action = ?config.action,
        "fault injection triggered"
    );

    match config.action {
        FaultAction::Abort => process::abort(),
        FaultAction::Sigkill => unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        },
        FaultAction::ReturnError => Err(format!("fault injection triggered at {}", point)),
        FaultAction::SleepMs(ms) => {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(())
        }
    }
}

fn mark_once(path: &str, point: &str, hit: u64) -> io::Result<bool> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(path))
    {
        Ok(mut file) => {
            writeln!(file, "point={} hit={}", point, hit)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
fn temp_once_path(name: &str) -> String {
    let suffix = MATCHED_HITS.fetch_add(1, Ordering::SeqCst);
    env::temp_dir()
        .join(format!("aria-fault-injection-{}-{}", name, suffix))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
fn remove_file_if_exists(path: &str) {
    if Path::new(path).exists() {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_config_matches_exact_point_or_wildcard() {
        let exact = FaultConfig {
            point: "neutron.acl.after_purge".to_string(),
            after_hits: 1,
            action: FaultAction::ReturnError,
            once_file: None,
        };
        assert!(exact.matches("neutron.acl.after_purge"));
        assert!(!exact.matches("neutron.acl.after_group_write"));

        let wildcard = FaultConfig {
            point: "*".to_string(),
            after_hits: 1,
            action: FaultAction::ReturnError,
            once_file: None,
        };
        assert!(wildcard.matches("neutron.acl.after_purge"));
        assert!(wildcard.matches("neutron.snapshot.before_commit"));
    }

    #[test]
    fn mark_once_creates_marker_only_once() {
        let path = temp_once_path("marker");
        remove_file_if_exists(&path);

        assert!(mark_once(&path, "neutron.acl.after_policy_write", 1).unwrap());
        assert!(!mark_once(&path, "neutron.acl.after_policy_write", 2).unwrap());

        let marker = fs::read_to_string(&path).unwrap();
        assert!(marker.contains("point=neutron.acl.after_policy_write"));
        assert!(marker.contains("hit=1"));

        remove_file_if_exists(&path);
    }
}
