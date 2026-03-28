use crate::{api_client, cli::ChainCommands};

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    action: ChainCommands,
) -> Result<(), String> {
    match action {
        ChainCommands::Apply { file } => {
            let json_str = match std::fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: Failed to read file '{}': {}", file, e);
                    std::process::exit(1);
                }
            };
            let req: aria_api::CreateServiceChainRequest = match serde_json::from_str(&json_str) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: Invalid JSON: {}", e);
                    std::process::exit(1);
                }
            };
            match client.create_chain(&req).await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        ChainCommands::List => match client.list_chains().await {
            Ok(resp) => {
                if resp.chains.is_empty() {
                    println!("No service chains configured");
                } else {
                    println!("{:<20} {:<30} {}", "Name", "Description", "Hops");
                    for c in &resp.chains {
                        let hop_names: Vec<&str> =
                            c.hops.iter().map(|h| h.name.as_str()).collect();
                        println!("{:<20} {:<30} {}", c.name, c.description, hop_names.join(" → "));
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        ChainCommands::Show { name } => match client.get_chain(&name).await {
            Ok(chain) => {
                println!("Chain: {}", chain.name);
                if !chain.description.is_empty() {
                    println!("Description: {}", chain.description);
                }
                println!();
                for (i, hop) in chain.hops.iter().enumerate() {
                    println!("  Hop #{}: {} ({})", i + 1, hop.name, hop.hop_type);
                    for tap in &hop.taps {
                        println!("    tap: {} ({})", tap.tap, tap.role);
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        ChainCommands::Delete { name } => match client.delete_chain(&name).await {
            Ok(resp) => {
                println!("{}", resp.message);
                Ok(())
            }
            Err(e) => Err(e),
        },
    }
}
