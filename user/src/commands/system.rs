use crate::{api_client, cli::SystemCommands};

pub(crate) async fn handle_system_action(
    client: &api_client::ApiClient,
    has_tap: bool,
    action: SystemCommands,
) -> Result<(), String> {
    match action {
        SystemCommands::Start {
            iface,
            max_port_policies,
        } => {
            if has_tap {
                eprintln!(
                    "Error: 'system start' cannot be used with --tap. Use aria-agent to manage tap instances."
                );
                std::process::exit(1);
            }
            match client
                .system_start(&aria_api::SystemStartRequest {
                    iface,
                    max_port_policies,
                })
                .await
            {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SystemCommands::Stop => {
            if has_tap {
                eprintln!(
                    "Error: 'system stop' cannot be used with --tap. Use aria-agent to manage tap instances."
                );
                std::process::exit(1);
            }
            match client.system_stop().await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }
}

pub(crate) async fn handle_instances(client: &api_client::ApiClient) -> Result<(), String> {
    match client.list_instances().await {
        Ok(resp) => {
            if resp.instances.is_empty() {
                println!("No instances registered");
            } else {
                println!("{:<20} {}", "Instance", "Status");
                for inst in &resp.instances {
                    let status = if inst.active { "active" } else { "inactive" };
                    println!("{:<20} {}", inst.name, status);
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) async fn handle_health(client: &api_client::ApiClient) -> Result<(), String> {
    match client.health().await {
        Ok(resp) => {
            println!("Status:    {}", resp.status);
            println!("Version:   {}", resp.version);
            println!("Instances: {}", resp.instances);
            println!(
                "KernelDrop: {}",
                if resp.kernel_drop_available {
                    "available"
                } else {
                    "unavailable"
                }
            );
            if let Some(mode) = &resp.kernel_drop_mode {
                println!("DropMode:  {}", mode);
            }
            println!("DropIfaces: {}", resp.kernel_drop_managed_ifaces);
            if let Some(last_error) = &resp.kernel_drop_last_error {
                println!("DropError: {}", last_error);
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}
