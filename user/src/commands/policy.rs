use crate::{api_client, cli::PolicyCommands};

fn print_bitmap_cleanup_pending(pending: &[aria_api::BitmapCleanupPendingResponse]) {
    if pending.is_empty() {
        return;
    }
    eprintln!(
        "Warning: policy committed with {} bitmap cleanup operation(s) pending:",
        pending.len()
    );
    for cleanup in pending {
        eprintln!(
            "  bitmap {} ({}): {}",
            cleanup.bitmap_idx, cleanup.ports_normalized, cleanup.error
        );
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PolicyBatchInput {
    Wrapped(aria_api::BatchAddPoliciesRequest),
    Bare(Vec<aria_api::AddPolicyRequest>),
}

fn parse_batch_add_policies(
    json_str: &str,
) -> Result<aria_api::BatchAddPoliciesRequest, serde_json::Error> {
    match serde_json::from_str::<PolicyBatchInput>(json_str)? {
        PolicyBatchInput::Wrapped(req) => Ok(req),
        PolicyBatchInput::Bare(policies) => Ok(aria_api::BatchAddPoliciesRequest { policies }),
    }
}

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
            ethertype,
        } => {
            match client
                .add_policy(
                    instance,
                    &aria_api::AddPolicyRequest {
                        ethertype,
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
                    print_bitmap_cleanup_pending(&resp.cleanup_pending);
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
            ethertype,
        } => {
            match client
                .delete_policy(
                    instance,
                    &aria_api::DeletePolicyRequest {
                        ethertype,
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
                    print_bitmap_cleanup_pending(&resp.cleanup_pending);
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

            let req = match parse_batch_add_policies(&json_str) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Error: Invalid JSON: {}", e);
                    std::process::exit(1);
                }
            };

            match client.batch_add_policies(instance, &req).await {
                Ok(resp) => {
                    println!("Batch complete: {} added", resp.added);
                    if !resp.errors.is_empty() {
                        eprintln!("Errors:");
                        for err in &resp.errors {
                            eprintln!("  {}", err);
                        }
                        std::process::exit(1);
                    }
                    print_bitmap_cleanup_pending(&resp.cleanup_pending);
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

#[cfg(test)]
mod tests {
    use super::{parse_batch_add_policies, policy_table_headers};

    #[test]
    fn acl_family_cli_list_and_with_stats_render_ethertype() {
        assert!(policy_table_headers(false).contains(&"Ethertype"));
        assert!(policy_table_headers(true).contains(&"Ethertype"));
    }

    #[test]
    fn parse_batch_accepts_documented_wrapper() {
        let req = parse_batch_add_policies(
            r#"{"policies":[{"src_group":"any","dst_group":"web","proto":"tcp","action":"accept","direction":"ingress","ports":"443"}]}"#,
        )
        .expect("wrapper payload should parse");

        assert_eq!(req.policies.len(), 1);
        assert_eq!(req.policies[0].dst_group, "web");
        assert_eq!(req.policies[0].ports.as_deref(), Some("443"));
    }

    #[test]
    fn parse_batch_accepts_legacy_array() {
        let req = parse_batch_add_policies(
            r#"[{"src_group":"any","dst_group":"db","proto":"tcp","action":"accept","direction":"egress","ports":"3306"}]"#,
        )
        .expect("legacy array payload should parse");

        assert_eq!(req.policies.len(), 1);
        assert_eq!(req.policies[0].dst_group, "db");
        assert_eq!(req.policies[0].ports.as_deref(), Some("3306"));
    }
}
