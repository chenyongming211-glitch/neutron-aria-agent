use std::env;
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

        Some(Self {
            point,
            after_hits,
            action,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_config_matches_exact_point_or_wildcard() {
        let exact = FaultConfig {
            point: "neutron.acl.after_purge".to_string(),
            after_hits: 1,
            action: FaultAction::ReturnError,
        };
        assert!(exact.matches("neutron.acl.after_purge"));
        assert!(!exact.matches("neutron.acl.after_group_write"));

        let wildcard = FaultConfig {
            point: "*".to_string(),
            after_hits: 1,
            action: FaultAction::ReturnError,
        };
        assert!(wildcard.matches("neutron.acl.after_purge"));
        assert!(wildcard.matches("neutron.snapshot.before_commit"));
    }
}
