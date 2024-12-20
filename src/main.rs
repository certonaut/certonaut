use anyhow::Context;
use certonaut::config::CONFIG_FILE;
use certonaut::interactive::InteractiveService;
use certonaut::{config, Certonaut, IssueCommand};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
fn get_default_config_directory() -> PathBuf {
    PathBuf::from("/etc/certonaut")
}

#[cfg(target_os = "windows")]
fn get_default_config_directory() -> PathBuf {
    let app_data = std::env::var("LOCALAPPDATA").expect("No LOCALAPPDATA directory");
    PathBuf::from(app_data).join("certonaut")
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
struct CommandLineArguments {
    /// Path to configuration directory
    #[arg(short, long, env = "CERTONAUT_CONFIG", default_value_os_t = get_default_config_directory())]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Issue a new certificate
    Issue(IssueCommand),
}

fn is_interactive() -> bool {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    stdin.is_terminal() && stdout.is_terminal() && stderr.is_terminal()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_env("CERTONAUT_LOG")
        .unwrap_or_else(|_| EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("info")));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    // TODO: Refactor
    let sup = certonaut::magic::is_supported();
    info!("Magic supported: {sup}");
    let interactive = is_interactive();
    let cli = CommandLineArguments::parse();
    CONFIG_FILE.set(cli.config).expect("Config file already set");
    let config = config::load()?;
    let client = Certonaut::try_new(config).context("Loading configuration failed")?;

    let result = {
        match cli.command {
            None => {
                if interactive {
                    // TODO: Greeting & first-time instructions for new users here
                    // TODO: interactive selection of action
                }
                println!("Welcome! There's nothing here yet.");
                todo!()
            }
            Some(Commands::Issue(issue_cmd)) => {
                if interactive {
                    let mut interactive_client = InteractiveService::new(client);
                    interactive_client.interactive_issuance(issue_cmd).await
                } else {
                    todo!("Non-interactive issuance")
                }
            }
        }
    };
    // Wrap last line to avoid anyhow conflicts with the interactive terminal
    println!();
    result
}
