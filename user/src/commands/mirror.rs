use crate::{api_client, cli::MirrorCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: MirrorCommands,
) -> Result<(), String> {
    match action {
        MirrorCommands::Add {
            direction,
            target,
            src_group,
            dst_group,
            proto,
        } => {
            match client
                .add_mirror(
                    instance,
                    &aria_api::AddMirrorRequest {
                        src_group,
                        dst_group,
                        proto,
                        direction,
                        target,
                    },
                )
                .await
            {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        MirrorCommands::Delete {
            direction,
            src_group,
            dst_group,
            proto,
        } => {
            match client
                .delete_mirror(
                    instance,
                    &aria_api::DeleteMirrorRequest {
                        src_group,
                        dst_group,
                        proto,
                        direction,
                    },
                )
                .await
            {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        MirrorCommands::List => match client.list_mirror(instance).await {
            Ok(resp) => {
                if resp.rules.is_empty() {
                    println!("No mirror rules configured");
                } else {
                    println!(
                        "{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {}",
                        "SrcGroup", "DstGroup", "Proto", "Direction", "Target", "IfIdx", "Global"
                    );
                    for r in &resp.rules {
                        println!(
                            "{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {}",
                            r.src_group,
                            r.dst_group,
                            r.proto,
                            r.direction,
                            r.target_iface,
                            r.target_ifindex,
                            if r.is_global { "yes" } else { "no" }
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        MirrorCommands::WithStats => match client.list_mirror_with_stats(instance).await {
            Ok(resp) => {
                if resp.rules.is_empty() {
                    println!("No mirror rules configured");
                } else {
                    println!(
                        "{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {:>12} {:>12} {}",
                        "SrcGroup",
                        "DstGroup",
                        "Proto",
                        "Direction",
                        "Target",
                        "Global",
                        "MirrorPkts",
                        "MirrorBytes",
                        "Errors"
                    );
                    for r in &resp.rules {
                        println!(
                            "{:<12} {:<12} {:<8} {:<10} {:<15} {:<8} {:>12} {:>12} {}",
                            r.src_group,
                            r.dst_group,
                            r.proto,
                            r.direction,
                            r.target_iface,
                            if r.is_global { "yes" } else { "no" },
                            r.mirrored_packets,
                            r.mirrored_bytes,
                            r.errors
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
