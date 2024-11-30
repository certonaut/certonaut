use anyhow::Context;
use certonaut::client::Rover;
use certonaut::config::DEFAULT_RPC;
use certonaut::rpc::client::RpcClient;
use clap::{Parser, Subcommand};
use std::io::IsTerminal;

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
struct Args {
    /// Address of the orbiter
    #[arg(short, long, default_value = DEFAULT_RPC, env = "RPC_URL")]
    connect: tonic::transport::Endpoint,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Issue a new certificate
    Issue {},
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
    let args = Args::parse();
    // TODO: Also consider grabbing RPC from the config file, if found at default location
    let rpc_endpoint = args.connect;
    let rpc_uri = rpc_endpoint.uri().clone();

    let rpc_client = RpcClient::try_new(rpc_endpoint).await.context(format!(
        "Cannot connect to orbiter at address {rpc_uri}. Did you launch it?"
    ))?;
    let mut rover = Rover::new(rpc_client);

    let result = {
        match args.command {
            None => {
                if interactive {
                    // TODO: Greeting & first-time instructions for new users here
                    // TODO: interactive selection of action
                }
                todo!()
            }
            Some(Commands::Issue {}) => {
                if interactive {
                    // TODO: Pre-apply CLI arguments
                    rover.interactive_issuance().await
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
