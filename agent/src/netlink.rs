use std::sync::Arc;
use futures::stream::TryStreamExt;
use futures::stream::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::LinkAttribute;
use netlink_sys::AsyncSocket;
use tracing::{info, warn};
use crate::control_plane::MANAGED_SHARED_PIN_NAMESPACE;
use crate::tap_registry::TapRegistry;

/// Enumerate all current network interfaces and return names matching the pattern
async fn scan_existing_interfaces(registry: &TapRegistry) -> Vec<String> {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to create rtnetlink connection for scan");
            return Vec::new();
        }
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let mut matched = Vec::new();

    while let Ok(Some(msg)) = links.try_next().await {
        for nla in &msg.attributes {
            if let LinkAttribute::IfName(name) = nla {
                if registry.matches_pattern(name) {
                    matched.push(name.clone());
                }
            }
        }
    }

    matched
}

/// Clean up orphaned pin directories that don't correspond to any existing interface
fn cleanup_orphaned_pins(base_pin_path: &str, existing_ifaces: &[String]) {
    let base = std::path::Path::new(base_pin_path);
    if !base.exists() {
        return;
    }

    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, path = %base_pin_path, "failed to read pin directory for cleanup");
            return;
        }
    };

    for entry in entries {
        if let Ok(entry) = entry {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    // Skip special directories managed outside tap lifecycle.
                    if name == "system"
                        || name == "ssl-global"
                        || name == MANAGED_SHARED_PIN_NAMESPACE
                    {
                        continue;
                    }
                    if !existing_ifaces.contains(&name.to_string()) {
                        info!(pin = %name, "cleaning orphaned pin directory");
                        if let Err(e) = std::fs::remove_dir_all(entry.path()) {
                            warn!(pin = %name, error = %e, "failed to remove orphaned pin directory");
                        }
                    }
                }
            }
        }
    }
}

/// Reconcile registry with actual interfaces: attach missing, detach stale
async fn reconcile(registry: &Arc<TapRegistry>) {
    let existing = scan_existing_interfaces(registry).await;
    let managed = registry.list().await;

    // Attach any new interfaces not yet managed
    for iface in &existing {
        if !managed.contains(iface) {
            info!(instance = %iface, "reconcile detected unmanaged tap");
            if let Err(e) = registry.attach(iface).await {
                warn!(instance = %iface, error = %e, "reconcile failed to attach interface");
            }
        }
    }

    // Detach any managed interfaces that no longer exist
    for iface in &managed {
        if !existing.contains(iface) {
            info!(instance = %iface, "reconcile detected disappeared interface");
            if let Err(e) = registry.detach(iface).await {
                warn!(instance = %iface, error = %e, "reconcile failed to detach interface");
            }
        }
    }
}

/// Main netlink monitoring loop.
/// 1. Scans existing interfaces on startup
/// 2. Cleans orphaned pins
/// 3. Listens for RTM_NEWLINK/RTM_DELLINK events
/// 4. Periodically reconciles (every 60s) as a safety net
pub async fn monitor(registry: Arc<TapRegistry>) -> Result<(), String> {
    // 1. Initial scan
    let existing = scan_existing_interfaces(&registry).await;
    info!(count = existing.len(), interfaces = ?existing, "initial netlink scan complete");

    // 2. Clean orphaned pins
    cleanup_orphaned_pins(
        registry.base_pin_path.to_str().unwrap(),
        &existing,
    );

    // 3. Attach all existing tap interfaces
    for iface in &existing {
        if let Err(e) = registry.attach(iface).await {
            warn!(instance = %iface, error = %e, "startup attach failed");
        }
    }

    // 4. Set up netlink event listener with RTMGRP_LINK multicast subscription
    let (mut connection, _, mut messages) = rtnetlink::new_connection()
        .map_err(|e| format!("Failed to create rtnetlink connection: {}", e))?;

    // Join the RTNLGRP_LINK multicast group via bind
    let mgroup_flags = rtnetlink::constants::RTMGRP_LINK;
    let addr = netlink_sys::SocketAddr::new(0, mgroup_flags);
    connection.socket_mut().socket_mut()
        .bind(&addr)
        .map_err(|e| format!("Failed to bind RTMGRP_LINK: {}", e))?;

    tokio::spawn(connection);

    // 5. Event loop with periodic reconciliation
    let mut reconcile_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    // Don't reconcile immediately (we just did the initial scan)
    reconcile_interval.tick().await;

    loop {
        tokio::select! {
            msg = messages.next() => {
                match msg {
                    Some((message, _)) => {
                        handle_netlink_message(&registry, message).await;
                    }
                    None => {
                        warn!("netlink stream ended; restarting monitor");
                        break;
                    }
                }
            }
            _ = reconcile_interval.tick() => {
                reconcile(&registry).await;
            }
        }
    }

    Ok(())
}

/// Process a single netlink message, looking for link add/remove events
async fn handle_netlink_message(
    registry: &Arc<TapRegistry>,
    message: netlink_packet_core::NetlinkMessage<RouteNetlinkMessage>,
) {
    match message.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) => {
            let iface_name = msg.attributes.iter().find_map(|nla| {
                if let LinkAttribute::IfName(name) = nla {
                    Some(name.clone())
                } else {
                    None
                }
            });

            if let Some(name) = iface_name {
                if registry.matches_pattern(&name) {
                    info!(instance = %name, "received netlink NewLink");
                    // Small delay to let the interface fully initialize
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if let Err(e) = registry.attach(&name).await {
                        warn!(instance = %name, error = %e, "failed to attach interface after NewLink");
                    }
                }
            }
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
            let iface_name = msg.attributes.iter().find_map(|nla| {
                if let LinkAttribute::IfName(name) = nla {
                    Some(name.clone())
                } else {
                    None
                }
            });

            if let Some(name) = iface_name {
                if registry.matches_pattern(&name) {
                    info!(instance = %name, "received netlink DelLink");
                    if let Err(e) = registry.detach(&name).await {
                        warn!(instance = %name, error = %e, "failed to detach interface after DelLink");
                    }
                }
            }
        }
        _ => {}
    }
}
