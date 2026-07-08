use crate::{api_client, cli::DropsCommands};

pub(crate) fn kernel_drop_query_from_cli(
    tap: Option<&String>,
    iface: Option<String>,
    top: Option<usize>,
    include_unattributed: bool,
) -> aria_api::KernelDropQuery {
    aria_api::KernelDropQuery {
        instance: tap.cloned(),
        iface,
        ifindex: None,
        reason: None,
        top,
        include_unattributed,
    }
}

pub(crate) fn print_kernel_drop_stats(entries: &[aria_api::KernelDropStatsEntry]) {
    // Check if any entry has location data
    let has_location = entries.iter().any(|e| e.location.is_some());

    if has_location {
        println!(
            "{:<16} {:<16} {:<8} {:<20} {:<10} {:>10} {:>10} {:<22} {:<30} {}",
            "Instance",
            "Iface",
            "Ifindex",
            "Reason",
            "Proto",
            "Packets",
            "Bytes",
            "Source",
            "Location",
            "Hint"
        );
        for entry in entries {
            println!(
                "{:<16} {:<16} {:<8} {:<20} {:<10} {:>10} {:>10} {:<22} {:<30} {}",
                entry.instance.as_deref().unwrap_or("-"),
                entry.iface.as_deref().unwrap_or("-"),
                entry.ifindex,
                entry.reason,
                entry.proto,
                entry.packets,
                entry.bytes,
                entry.source,
                entry.location.as_deref().unwrap_or("-"),
                entry.location_hint.as_deref().unwrap_or(""),
            );
        }
    } else {
        println!(
            "{:<16} {:<16} {:<8} {:<20} {:<10} {:>12} {:>12} {}",
            "Instance", "Iface", "Ifindex", "Reason", "Proto", "Packets", "Bytes", "Source"
        );
        for entry in entries {
            println!(
                "{:<16} {:<16} {:<8} {:<20} {:<10} {:>12} {:>12} {}",
                entry.instance.as_deref().unwrap_or("-"),
                entry.iface.as_deref().unwrap_or("-"),
                entry.ifindex,
                entry.reason,
                entry.proto,
                entry.packets,
                entry.bytes,
                entry.source,
            );
        }
    }
}

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    tap_filter: Option<&String>,
    action: DropsCommands,
) -> Result<(), String> {
    match action {
        DropsCommands::List {
            iface,
            top,
            include_unattributed,
        } => {
            let query =
                kernel_drop_query_from_cli(tap_filter, iface, Some(top), include_unattributed);
            match client.list_kernel_drops(&query).await {
                Ok(resp) => {
                    if resp.drops.is_empty() {
                        println!("No kernel drops recorded");
                    } else {
                        print_kernel_drop_stats(&resp.drops);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        DropsCommands::Flush {
            iface,
            include_unattributed,
            force,
        } => {
            if !force {
                Err("Refusing to flush kernel-drop statistics without --force".to_string())
            } else {
                let query =
                    kernel_drop_query_from_cli(tap_filter, iface, None, include_unattributed);
                match client.flush_kernel_drops(&query).await {
                    Ok(resp) => {
                        println!("Flushed {} kernel drop entries", resp.flushed);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}
