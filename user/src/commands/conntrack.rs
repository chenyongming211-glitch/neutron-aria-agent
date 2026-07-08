use crate::{api_client, cli::ConntrackCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: ConntrackCommands,
) -> Result<(), String> {
    match action {
        ConntrackCommands::List => match client.list_conntrack(instance).await {
            Ok(resp) => {
                if resp.connections.is_empty() {
                    println!("No active connections");
                } else {
                    println!(
                        "{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                        "Source",
                        "Destination",
                        "SPort",
                        "DPort",
                        "Proto",
                        "State",
                        "Packets",
                        "Bytes"
                    );
                    for c in &resp.connections {
                        println!(
                            "{:<20} {:<20} {:<8} {:<8} {:<8} {:<12} {:<15} {}",
                            c.src_ip,
                            c.dst_ip,
                            c.src_port,
                            c.dst_port,
                            c.proto,
                            c.state,
                            c.packets,
                            c.bytes
                        );
                    }
                    println!("\nTotal: {} connections", resp.total);
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        ConntrackCommands::Flush => match client.flush_conntrack(instance).await {
            Ok(resp) => {
                println!("Flushed {} connections", resp.flushed);
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
