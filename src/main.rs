use certonaut::interactive::InteractiveClient;
use certonaut::{config, Certonaut, IssueCommand, CONFIG_FILE};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
struct CommandLineArguments {
    /// Path to configuration file
    #[arg(
        short,
        long,
        env = "CERTONAUT_CONFIG",
        default_value = "certonaut.toml"
    )]
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
    let interactive = is_interactive();
    let cli = CommandLineArguments::parse();
    CONFIG_FILE
        .set(cli.config.clone())
        .expect("Config file already set");
    let config = config::load(cli.config)?;
    let client = Certonaut::new(config);

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
                    let mut interactive_client = InteractiveClient::new(client);
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
