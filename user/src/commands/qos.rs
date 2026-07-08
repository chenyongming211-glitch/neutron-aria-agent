use crate::{api_client, cli::QosCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: QosCommands,
) -> Result<(), String> {
    match action {
        QosCommands::Add {
            group,
            direction,
            rate,
            burst,
            priority,
            mode,
        } => {
            match client
                .add_qos(
                    instance,
                    &aria_api::AddQosRequest {
                        group,
                        direction,
                        rate,
                        burst,
                        priority,
                        mode,
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
        QosCommands::Delete { group, direction } => {
            match client
                .delete_qos(instance, &aria_api::DeleteQosRequest { group, direction })
                .await
            {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        QosCommands::List => match client.list_qos(instance).await {
            Ok(resp) => {
                if resp.rules.is_empty() {
                    println!("No QoS rules configured");
                } else {
                    println!(
                        "{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {}",
                        "Group",
                        "GroupID",
                        "Direction",
                        "Rate (B/s)",
                        "Burst (B)",
                        "Mode",
                        "Priority"
                    );
                    for r in &resp.rules {
                        println!(
                            "{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {}",
                            r.group,
                            r.group_id,
                            r.direction,
                            r.rate_bps,
                            r.burst_bytes,
                            r.mode,
                            r.priority
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        QosCommands::WithStats => match client.list_qos_with_stats(instance).await {
            Ok(resp) => {
                if resp.rules.is_empty() {
                    println!("No QoS rules configured");
                } else {
                    println!(
                        "{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {}",
                        "Group",
                        "GroupID",
                        "Direction",
                        "Rate (B/s)",
                        "Burst (B)",
                        "Mode",
                        "PassPkts",
                        "PassBytes",
                        "DropPkts",
                        "DropBytes",
                        "ShapePkts",
                        "ShapeBytes",
                        "Priority"
                    );
                    for r in &resp.rules {
                        println!(
                            "{:<15} {:<10} {:<10} {:<15} {:<15} {:<10} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {}",
                            r.group,
                            r.group_id,
                            r.direction,
                            r.rate_bps,
                            r.burst_bytes,
                            r.mode,
                            r.passed_packets,
                            r.passed_bytes,
                            r.dropped_packets,
                            r.dropped_bytes,
                            r.shaped_packets,
                            r.shaped_bytes,
                            r.priority
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
