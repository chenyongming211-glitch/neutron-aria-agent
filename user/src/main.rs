use clap::Parser;

mod api_client;
mod cli;
mod commands;

use self::cli::{Cli, Commands, TraceCommands};

fn get_instance(cli: &Cli) -> String {
    cli.tap.clone().unwrap_or_else(|| "system".to_string())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = api_client::ApiClient::new(&cli.api_url);
    let instance = get_instance(&cli);
    let has_tap = cli.tap.is_some();
    let tap_filter = cli.tap.clone();

    let result: Result<(), String> = match cli.command {
        Commands::System { action } => commands::system::handle_system_action(&client, has_tap, action).await,
        Commands::Group { action } => commands::group::handle_action(&client, &instance, action).await,
        Commands::Policy { action } => commands::policy::handle_action(&client, &instance, action).await,
        Commands::Stats { rules, flows, top, qos, groups, mirror, tcprt, drops } => {
            commands::stats::handle(
                &client,
                &instance,
                tap_filter.as_ref(),
                rules,
                flows,
                top,
                qos,
                groups,
                mirror,
                tcprt,
                drops,
            )
            .await
        },
        Commands::Conntrack { action } => commands::conntrack::handle_action(&client, &instance, action).await,
        Commands::Qos { action } => commands::qos::handle_action(&client, &instance, action).await,
        Commands::Mirror { action } => commands::mirror::handle_action(&client, &instance, action).await,
        Commands::Tcprt { action } => commands::tcprt::handle_action(&client, &instance, action).await,
        Commands::Chain { action } => commands::chain::handle_action(&client, action).await,
        Commands::Drops { action } => commands::drops::handle_action(&client, tap_filter.as_ref(), action).await,
        Commands::Trace { action } => match action {
            TraceCommands::Start { tap, src, dst, sport, dport, proto, wait, chain } => {
                commands::trace::handle_trace_start(
                    &client,
                    tap,
                    src,
                    dst,
                    sport,
                    dport,
                    proto,
                    wait,
                    chain,
                )
                .await
            }
        },
        Commands::Ssl { action } => commands::ssl::handle_action(&client, &instance, has_tap, action).await,
        Commands::Config { action } => commands::config::handle_action(&client, &instance, has_tap, action).await,
        Commands::Diagnose { dst, dport, chain } => {
            commands::diagnose::handle(&client, &instance, &dst, dport, chain.as_deref()).await
        },
        Commands::Instances => commands::system::handle_instances(&client).await,
        Commands::Health => commands::system::handle_health(&client).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    };
}
