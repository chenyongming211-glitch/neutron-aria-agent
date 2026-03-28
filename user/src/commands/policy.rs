use crate::{api_client, cli::PolicyCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: PolicyCommands,
) -> Result<(), String> {
    match action {
        PolicyCommands::Add {
            src_group,
            dst_group,
            proto,
            action,
            ports,
            direction,
        } => {
            match client
                .add_policy(
                    instance,
                    &aria_api::AddPolicyRequest {
                        src_group: src_group.clone(),
                        dst_group: dst_group.clone(),
                        proto,
                        action,
                        direction: direction.clone(),
                        ports,
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
        PolicyCommands::Delete {
            src_group,
            dst_group,
            proto,
            direction,
        } => {
            match client
                .delete_policy(
                    instance,
                    &aria_api::DeletePolicyRequest {
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
        PolicyCommands::Batch { file } => {
            let json_str = if file == "-" {
                use std::io::Read;
                let mut buf = String::new();
                match std::io::stdin().read_to_string(&mut buf) {
                    Ok(_) => buf,
                    Err(e) => {
                        eprintln!("Error: Failed to read stdin: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                match std::fs::read_to_string(&file) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error: Failed to read file '{}': {}", file, e);
                        std::process::exit(1);
                    }
                }
            };

            let policies: Vec<aria_api::AddPolicyRequest> = match serde_json::from_str(&json_str) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: Invalid JSON: {}", e);
                    std::process::exit(1);
                }
            };

            match client
                .batch_add_policies(instance, &aria_api::BatchAddPoliciesRequest { policies })
                .await
            {
                Ok(resp) => {
                    println!("Batch complete: {} added", resp.added);
                    if !resp.errors.is_empty() {
                        eprintln!("Errors:");
                        for err in &resp.errors {
                            eprintln!("  {}", err);
                        }
                        std::process::exit(1);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        PolicyCommands::List => match client.list_policies(instance).await {
            Ok(resp) => {
                if resp.policies.is_empty() {
                    println!("No policies configured");
                } else {
                    println!(
                        "{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {}",
                        "SrcGroup", "DstGroup", "Proto", "Action", "Direction", "Bitmap", "Ports"
                    );
                    for p in &resp.policies {
                        let bitmap_str = match p.bitmap_idx {
                            Some(idx) => idx.to_string(),
                            None => "-".to_string(),
                        };
                        println!(
                            "{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {}",
                            p.src_group,
                            p.dst_group,
                            p.proto,
                            p.action,
                            p.direction,
                            bitmap_str,
                            p.ports.as_deref().unwrap_or("")
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        PolicyCommands::WithStats => match client.list_policies_with_stats(instance).await {
            Ok(resp) => {
                if resp.policies.is_empty() {
                    println!("No policies configured");
                } else {
                    println!(
                        "{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {:>12} {:>12} {:>12} {:>12} {}",
                        "SrcGroup",
                        "DstGroup",
                        "Proto",
                        "Action",
                        "Direction",
                        "Bitmap",
                        "Packets",
                        "Bytes",
                        "DropPkts",
                        "DropBytes",
                        "Ports"
                    );
                    for p in &resp.policies {
                        let bitmap_str = match p.bitmap_idx {
                            Some(idx) => idx.to_string(),
                            None => "-".to_string(),
                        };
                        println!(
                            "{:<12} {:<12} {:<8} {:<8} {:<10} {:<8} {:>12} {:>12} {:>12} {:>12} {}",
                            p.src_group,
                            p.dst_group,
                            p.proto,
                            p.action,
                            p.direction,
                            bitmap_str,
                            p.packets,
                            p.bytes,
                            p.dropped_packets,
                            p.dropped_bytes,
                            p.ports.as_deref().unwrap_or("")
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
