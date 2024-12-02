use clap::Args;

pub mod acme;
pub mod client;
pub mod config;
pub mod crypto;
pub mod daemon;
pub mod pebble;
pub mod rpc;
pub mod util;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Debug, Args, Default)]
pub struct IssueCommand {
    /// ID of the CA to use
    #[clap(short, long)]
    ca: Option<String>,
    /// ID of the account to use
    #[clap(short, long)]
    account: Option<String>,
}