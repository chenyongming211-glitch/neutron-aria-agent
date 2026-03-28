use crate::{api_client, cli::SslCommands};

fn note_ssl_is_global(has_tap: bool) {
    if has_tap {
        eprintln!("Note: --tap is ignored for SSL observability commands; SSL data is host-global.");
    }
}

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    has_tap: bool,
    action: SslCommands,
) -> Result<(), String> {
    match action {
        SslCommands::List { top } => {
            note_ssl_is_global(has_tap);
            match client.list_ssl(instance, top).await {
                Ok(resp) => {
                    if resp.connections.is_empty() {
                        println!("No SSL handshake records");
                    } else {
                        println!(
                            "{:<8} {:<8} {:<15} {:<64} {}",
                            "PID", "TID", "Handshake(us)", "SNI", "Seq"
                        );
                        for e in &resp.connections {
                            println!(
                                "{:<8} {:<8} {:<15.1} {:<64} {}",
                                e.pid, e.tid, e.handshake_us, e.sni, e.seq
                            );
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Flush => {
            note_ssl_is_global(has_tap);
            match client.flush_ssl(instance).await {
                Ok(resp) => {
                    println!("Flushed {} SSL handshake entries", resp.flushed);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Http { top } => {
            note_ssl_is_global(has_tap);
            match client.list_ssl_http(instance, top).await {
                Ok(resp) => {
                    if resp.events.is_empty() {
                        println!("No SSL HTTP events");
                    } else {
                        println!(
                            "{:<8} {:<8} {:<8} {:<23} {:<30} {:<8} {}",
                            "PID", "TID", "Method", "Host", "Path", "Status", "Latency(us)"
                        );
                        for e in &resp.events {
                            println!(
                                "{:<8} {:<8} {:<8} {:<23} {:<30} {:<8} {:.1}",
                                e.pid,
                                e.tid,
                                e.method,
                                e.host,
                                e.path,
                                e.status_code,
                                e.latency_us
                            );
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::HttpFlush => {
            note_ssl_is_global(has_tap);
            match client.flush_ssl_http(instance).await {
                Ok(resp) => {
                    println!("Flushed {} SSL HTTP entries", resp.flushed);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Enable => {
            note_ssl_is_global(has_tap);
            match client.update_ssl_config(true).await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Disable => {
            note_ssl_is_global(has_tap);
            match client.update_ssl_config(false).await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Status => {
            note_ssl_is_global(has_tap);
            match client.get_ssl_config().await {
                Ok(cfg) => {
                    println!(
                        "Global SSL Observability: {}",
                        if cfg.enabled { "ENABLED" } else { "DISABLED" }
                    );
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::Errors { top } => {
            note_ssl_is_global(has_tap);
            match client.list_ssl_errors().await {
                Ok(resp) => {
                    if resp.errors.is_empty() {
                        println!("No SSL errors");
                    } else {
                        let display: Vec<_> = resp.errors.into_iter().take(top).collect();
                        println!(
                            "{:<8} {:<8} {:<8} {:<18} {:<10} {:<12}",
                            "PID", "TID", "SYSCALL", "TIMESTAMP", "RET", "HINT"
                        );
                        for e in &display {
                            println!(
                                "{:<8} {:<8} {:<8} {:<18} {:<10} {:<12}",
                                e.pid, e.tid, e.syscall, e.timestamp, e.ret_code, e.error_hint
                            );
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        SslCommands::ErrorsFlush => {
            note_ssl_is_global(has_tap);
            match client.flush_ssl_errors().await {
                Ok(resp) => {
                    println!("Flushed {} SSL errors", resp.flushed);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }
}
