use crate::{api_client, cli::GroupCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: GroupCommands,
) -> Result<(), String> {
    match action {
        GroupCommands::Add { name, cidr } => {
            match client
                .add_group(instance, &aria_api::AddGroupRequest { name, cidr })
                .await
            {
                Ok(resp) => {
                    println!("Added group '{}' with id {}", resp.name, resp.id);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        GroupCommands::Delete { name } => match client.delete_group(instance, &name).await {
            Ok(resp) => {
                println!("{}", resp.message);
                Ok(())
            }
            Err(e) => Err(e),
        },
        GroupCommands::List => match client.list_groups(instance).await {
            Ok(resp) => {
                if resp.groups.is_empty() {
                    println!("No groups configured");
                } else {
                    println!("{:<10} {:<15} {}", "ID", "Name", "CIDRs");
                    for g in &resp.groups {
                        println!("{:<10} {:<15} {}", g.id, g.name, g.cidrs.join(", "));
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        GroupCommands::WithStats => match client.list_groups_with_stats(instance).await {
            Ok(resp) => {
                if resp.groups.is_empty() {
                    println!("No groups configured");
                } else {
                    println!(
                        "{:<10} {:<15} {:>15} {:>15} {:>15} {:>15} {}",
                        "ID", "Name", "InPkts", "InBytes", "OutPkts", "OutBytes", "CIDRs"
                    );
                    for g in &resp.groups {
                        println!(
                            "{:<10} {:<15} {:>15} {:>15} {:>15} {:>15} {}",
                            g.id,
                            g.name,
                            g.ingress_packets,
                            g.ingress_bytes,
                            g.egress_packets,
                            g.egress_bytes,
                            g.cidrs.join(", ")
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
