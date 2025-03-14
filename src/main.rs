use anyhow::Context;
use certonaut::cli::{process_cli_command, setup_command_line};
use certonaut::config::CONFIG_FILE;
use certonaut::{Certonaut, config};
use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

const ENV_FILTER_NAME: &str = "CERTONAUT_LOG";

fn is_interactive() -> bool {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    stdin.is_terminal() && stdout.is_terminal() && stderr.is_terminal()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (cli, matches) = setup_command_line()?;
    let filter = EnvFilter::try_from_env(ENV_FILTER_NAME).unwrap_or_else(|_| {
        EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| {
            EnvFilter::new(if cli.verbose {
                "certonaut=debug,info"
            } else {
                "info"
            })
        })
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let interactive = is_interactive() && !cli.noninteractive;
    CONFIG_FILE
        .set(cli.config)
        .expect("Config file already set");
    let config = config::new_configuration_manager_with_default_config()?;
    let client = Certonaut::try_new(config)
        .await
        .context("Loading configuration failed")?;
    let result = process_cli_command(cli.command, &matches, client, interactive).await;
    if interactive && result.is_err() {
        // Wrap last line to avoid anyhow conflicts with the interactive terminal
        println!();
    }
    result
}
