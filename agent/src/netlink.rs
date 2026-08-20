use crate::control_plane::MANAGED_SHARED_PIN_NAMESPACE;
use crate::kernel_drop_manager::KERNEL_DROP_PIN_NAMESPACE;
use crate::tap_registry::TapRegistry;
use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::AsyncSocket;
use std::collections::BTreeSet;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LinkMonitorMode {
    AutoAttach,
    ManagedOnly,
}

fn should_process_link_event(
    mode: LinkMonitorMode,
    matches_pattern: bool,
    active: bool,
    authoritative: bool,
) -> bool {
    matches_pattern
        && (mode == LinkMonitorMode::AutoAttach || active || authoritative)
}

fn read_ifindex(iface: &str) -> Option<u32> {
    std::fs::read_to_string(std::path::Path::new("/sys/class/net").join(iface).join("ifindex"))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|ifindex| *ifindex != 0)
}

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
                        || name == KERNEL_DROP_PIN_NAMESPACE
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

/// Reconcile registry with actual interfaces according to the monitor's authority mode.
async fn reconcile(registry: &Arc<TapRegistry>, mode: LinkMonitorMode) {
    let existing = scan_existing_interfaces(registry).await;
    let existing_set = existing.iter().cloned().collect::<BTreeSet<_>>();
    let managed = registry.list().await;

    if mode == LinkMonitorMode::AutoAttach {
        for iface in &existing {
            if !managed.contains(iface) {
                info!(instance = %iface, "reconcile detected unmanaged tap");
                if let Err(e) = registry.link_ready(iface).await {
                    warn!(instance = %iface, error = %e, "reconcile failed to attach interface");
                }
            }
        }
        for iface in &managed {
            if !existing_set.contains(iface) {
                info!(instance = %iface, "reconcile detected disappeared interface");
                if let Err(e) = registry.link_deleted(iface, None).await {
                    warn!(instance = %iface, error = %e, "reconcile failed to detach interface");
                }
            }
        }
        return;
    }

    let authoritative = registry.neutron_authority_names().await;
    for iface in &managed {
        if authoritative.contains(iface) && !existing_set.contains(iface) {
            let (_, _, active_ifindex) = registry.link_observation_state(iface).await;
            info!(instance = %iface, "managed-only reconcile detected disappeared interface");
            if let Err(e) = registry.link_deleted(iface, active_ifindex).await {
                warn!(instance = %iface, error = %e, "managed-only reconcile failed to detach interface");
            }
        }
    }
    for iface in authoritative.intersection(&existing_set) {
        let (active, _, active_ifindex) = registry.link_observation_state(iface).await;
        let observed_ifindex = read_ifindex(iface);
        let identity_changed = matches!(
            (active_ifindex, observed_ifindex),
            (Some(active), Some(observed)) if active != observed
        );
        if !active || identity_changed {
            info!(
                instance = %iface,
                active_ifindex = ?active_ifindex,
                observed_ifindex = ?observed_ifindex,
                "managed-only reconcile detected available replacement interface"
            );
            if let Err(e) = registry.link_ready(iface).await {
                warn!(instance = %iface, error = %e, "managed-only reconcile failed to attach interface");
            }
        }
    }
}

/// Main netlink monitoring loop.
/// 1. Scans existing interfaces on startup
/// 2. Cleans orphaned pins
/// 3. Listens for RTM_NEWLINK/RTM_DELLINK events
/// 4. Periodically reconciles (every 60s) as a safety net
pub async fn monitor(registry: Arc<TapRegistry>, mode: LinkMonitorMode) -> Result<(), String> {
    // 1. Initial scan
    let existing = scan_existing_interfaces(&registry).await;
    info!(count = existing.len(), interfaces = ?existing, "initial netlink scan complete");

    if mode == LinkMonitorMode::AutoAttach {
        if let Some(pin_path) = registry.base_pin_path.to_str() {
            cleanup_orphaned_pins(pin_path, &existing);
        } else {
            warn!(
                path = %registry.base_pin_path.display(),
                "skip orphaned pin cleanup: non-UTF-8 base pin path"
            );
        }
        for iface in &existing {
            if let Err(e) = registry.link_ready(iface).await {
                warn!(instance = %iface, error = %e, "startup attach failed");
            }
        }
    } else {
        reconcile(&registry, mode).await;
    }

    // 4. Set up netlink event listener with RTMGRP_LINK multicast subscription
    let (mut connection, _, mut messages) = rtnetlink::new_connection()
        .map_err(|e| format!("Failed to create rtnetlink connection: {}", e))?;

    // Join the RTNLGRP_LINK multicast group via bind
    let mgroup_flags = rtnetlink::constants::RTMGRP_LINK;
    let addr = netlink_sys::SocketAddr::new(0, mgroup_flags);
    connection
        .socket_mut()
        .socket_mut()
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
                        handle_netlink_message(&registry, mode, message).await;
                    }
                    None => {
                        warn!("netlink stream ended; restarting monitor");
                        break;
                    }
                }
            }
            _ = reconcile_interval.tick() => {
                reconcile(&registry, mode).await;
            }
        }
    }

    Ok(())
}

/// Process a single netlink message, looking for link add/remove events
async fn handle_netlink_message(
    registry: &Arc<TapRegistry>,
    mode: LinkMonitorMode,
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
                let (active, authoritative, _) = registry.link_observation_state(&name).await;
                if should_process_link_event(
                    mode,
                    registry.matches_pattern(&name),
                    active,
                    authoritative,
                ) {
                    info!(instance = %name, "received netlink NewLink");
                    // Small delay to let the interface fully initialize
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if let Err(e) = registry.link_ready(&name).await {
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
                let (active, authoritative, _) = registry.link_observation_state(&name).await;
                if should_process_link_event(
                    mode,
                    registry.matches_pattern(&name),
                    active,
                    authoritative,
                ) {
                    info!(instance = %name, "received netlink DelLink");
                    if let Err(e) = registry.link_deleted(&name, Some(msg.header.index)).await {
                        warn!(instance = %name, error = %e, "failed to detach interface after DelLink");
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_only_monitor_handles_only_active_or_authoritative_taps() {
        assert!(should_process_link_event(
            LinkMonitorMode::ManagedOnly,
            true,
            false,
            true,
        ));
        assert!(should_process_link_event(
            LinkMonitorMode::ManagedOnly,
            true,
            true,
            false,
        ));
        assert!(!should_process_link_event(
            LinkMonitorMode::ManagedOnly,
            true,
            false,
            false,
        ));
        assert!(!should_process_link_event(
            LinkMonitorMode::ManagedOnly,
            false,
            true,
            true,
        ));
    }

    #[test]
    fn auto_attach_monitor_keeps_existing_pattern_behavior() {
        assert!(should_process_link_event(
            LinkMonitorMode::AutoAttach,
            true,
            false,
            false,
        ));
        assert!(!should_process_link_event(
            LinkMonitorMode::AutoAttach,
            false,
            true,
            true,
        ));
    }

}
