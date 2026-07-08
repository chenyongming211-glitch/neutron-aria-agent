use crate::{api_client, cli::ConfigCommands};

fn note_ssl_is_global(has_tap: bool) {
    if has_tap {
        eprintln!(
            "Note: --tap is ignored for SSL observability commands; SSL data is host-global."
        );
    }
}

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    has_tap: bool,
    action: ConfigCommands,
) -> Result<(), String> {
    match action {
        ConfigCommands::Show => match client.get_config(instance).await {
            Ok(cfg) => {
                println!("=== Firewall Configuration ===");
                println!("  conntrack:  {}", if cfg.conntrack { "on" } else { "off" });
                println!(
                    "  monitoring: {}",
                    if cfg.monitoring { "on" } else { "off" }
                );
                println!("  acl:        {}", if cfg.acl { "on" } else { "off" });
                println!("  qos:        {}", if cfg.qos { "on" } else { "off" });
                println!("  mirror:     {}", if cfg.mirror { "on" } else { "off" });
                println!("  tcprt:      {}", if cfg.tcprt { "on" } else { "off" });
                println!("  ssl:        {}", if cfg.ssl { "on" } else { "off" });
                println!("  num_cpus:   {}", cfg.num_cpus);
                Ok(())
            }
            Err(e) => Err(e),
        },
        ConfigCommands::Set { key, value } => {
            let enabled = match value.to_lowercase().as_str() {
                "on" | "true" | "1" | "yes" => true,
                "off" | "false" | "0" | "no" => false,
                _ => {
                    eprintln!("Error: invalid value '{}': must be 'on' or 'off'", value);
                    std::process::exit(1);
                }
            };

            if matches!(key.to_lowercase().as_str(), "ssl") {
                note_ssl_is_global(has_tap);
                match client.update_ssl_config(enabled).await {
                    Ok(_) => {
                        println!("Set ssl = {}", if enabled { "on" } else { "off" });
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                let req = match key.to_lowercase().as_str() {
                    "conntrack" | "ct" => aria_api::UpdateConfigRequest {
                        conntrack: Some(enabled),
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: None,
                        ssl: None,
                    },
                    "monitoring" | "mon" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: Some(enabled),
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: None,
                        ssl: None,
                    },
                    "acl" | "policy" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: Some(enabled),
                        qos: None,
                        mirror: None,
                        tcprt: None,
                        ssl: None,
                    },
                    "qos" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: Some(enabled),
                        mirror: None,
                        tcprt: None,
                        ssl: None,
                    },
                    "mirror" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: Some(enabled),
                        tcprt: None,
                        ssl: None,
                    },
                    "tcprt" | "tcp-rt" => aria_api::UpdateConfigRequest {
                        conntrack: None,
                        monitoring: None,
                        acl: None,
                        qos: None,
                        mirror: None,
                        tcprt: Some(enabled),
                        ssl: None,
                    },
                    _ => {
                        eprintln!(
                            "Error: unknown config key '{}': must be 'conntrack', 'monitoring', 'acl', 'qos', 'mirror', 'tcprt', or 'ssl'",
                            key
                        );
                        std::process::exit(1);
                    }
                };

                match client.update_config(instance, &req).await {
                    Ok(_) => {
                        println!("Set {} = {}", key, if enabled { "on" } else { "off" });
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}
