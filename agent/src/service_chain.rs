use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HopType {
    Bridge,
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TapRole {
    In,
    Out,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapBinding {
    pub tap: String,
    pub role: TapRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHop {
    pub name: String,
    pub hop_type: HopType,
    pub taps: Vec<TapBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChain {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub hops: Vec<ServiceHop>,
}

const CHAINS_FILE: &str = "service_chains.json";

pub fn load_chains(base_state_path: &str) -> Vec<ServiceChain> {
    let path = format!("{}/{}", base_state_path, CHAINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            warn!(path = %path, error = %e, "failed to parse service chain file");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

pub fn save_chains(base_state_path: &str, chains: &[ServiceChain]) -> Result<(), String> {
    let path = format!("{}/{}", base_state_path, CHAINS_FILE);
    let json = serde_json::to_string_pretty(chains)
        .map_err(|e| format!("Failed to serialize chains: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write {}: {}", path, e))
}
