use anyhow::Context;
use certonaut::config::CONFIG_FILE;
use certonaut::interactive::InteractiveService;
use certonaut::renew::RenewService;
use certonaut::CRATE_NAME;
use certonaut::{config, Certonaut, IssueCommand, RenewCommand};
use clap::{Parser, Subcommand};
use inquire::Select;
use std::fmt::Display;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
struct CommandLineArguments {
    /// Path to configuration directory
    #[arg(short, long, env = "CERTONAUT_CONFIG", default_value_os_t = config::get_default_config_directory())]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Issue a new certificate
    Issue(IssueCommand),
    /// Renew one or all certificates
    Renew(RenewCommand),
}

impl Display for Commands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Commands::Issue(_issue) => write!(f, "Issue a new certificate"),
            Commands::Renew(_renew) => write!(f, "Renew your certificates"),
        }
    }
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
    let mut cli = CommandLineArguments::parse();
    CONFIG_FILE.set(cli.config).expect("Config file already set");
    let config = config::load()?;
    let client = Certonaut::try_new(config).context("Loading configuration failed")?;

    let result = {
        loop {
            match cli.command {
                None => {
                    // TODO: Greeting & first-time instructions for new users here
                    if interactive {
                        println!("Welcome to {CRATE_NAME}!");
                        let selectable_commands = vec![
                            Commands::Issue(IssueCommand::default()),
                            Commands::Renew(RenewCommand::default()),
                        ];
                        let action = Select::new("What would you like to do?", selectable_commands)
                            .prompt()
                            .context("No action selected");
                        if let Ok(action) = action {
                            cli.command = Some(action);
                            continue;
                        }
                        break action.map(|_| ());
                    }
                    println!("Welcome! For non-interactive usage, an action (issue, renew) must be specified.");
                    todo!()
                }
                Some(Commands::Issue(issue_cmd)) => {
                    if interactive {
                        let mut service = InteractiveService::new(client);
                        break service.interactive_issuance(issue_cmd).await;
                    }
                    todo!("Non-interactive issuance")
                }
                Some(Commands::Renew(_renew_cmd)) => {
                    let service = RenewService::new(client, interactive);
                    break service.run().await;
                }
            }
        }
    };
    // Wrap last line to avoid anyhow conflicts with the interactive terminal
    println!();
    result
}
