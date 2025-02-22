use anyhow::{bail, Context};
use certonaut::config::CONFIG_FILE;
use certonaut::interactive::InteractiveService;
use certonaut::renew::RenewService;
use certonaut::CRATE_NAME;
use certonaut::{config, Certonaut};
use clap::{Parser, Subcommand};
use inquire::Select;
use std::fmt::Display;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use certonaut::cli::{IssueCommand, RenewCommand};

const ENV_FILTER_NAME: &str = "CERTONAUT_LOG";

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
struct CommandLineArguments {
    /// Path to configuration directory
    #[arg(short, long, env = "CERTONAUT_CONFIG", default_value_os_t = config::get_default_config_directory())]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
    /// Shorthand option to enable debug logging (logging can be fine-tuned via `CERTONAUT_LOG` environment variable)
    #[clap(long, short, action)]
    verbose: bool,
    /// Force certonaut to disable all interactive prompts, even if a terminal was detected
    #[clap(long, action)]
    noninteractive: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Shorthand for 'certificate issue'
    Issue(IssueCommand),
    /// Shorthand for 'certificate renew'
    Renew(RenewCommand),
    /// Create, edit, or view ACME accounts
    #[command(subcommand)]
    Account(AccountCommand),
    /// Issue, edit, or view certificates
    #[command(subcommand)]
    Certificate(CertificateCommand),
    /// Add, edit or view ACME-capable certificate authorities
    #[command(subcommand, name = "ca")]
    Issuer(IssuerCommand),
    #[command(hide = true)]
    InteractiveIssuer,
    #[command(hide = true)]
    InteractiveCertificate,
    #[command(hide = true)]
    InteractiveAccount,
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Command::Issue(_issue) => write!(f, "{}", CertificateCommand::Issue(IssueCommand::default())),
            Command::Renew(_renew) => write!(f, "{}", CertificateCommand::Renew(RenewCommand::default())),
            Command::InteractiveIssuer => write!(f, "Manage CAs"),
            Command::InteractiveCertificate => write!(f, "Manage certificates"),
            Command::InteractiveAccount => write!(f, "Manage ACME accounts"),
            _ => unimplemented!("BUG: Action display not configured"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    /// List accounts
    List,
    /// Create a new account
    Create,
    /// Import an existing account from another ACME client software
    Import,
    /// Change settings of an existing account
    Modify,
    /// Delete and deactivate an account
    Delete,
}

impl Display for AccountCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AccountCommand::List => write!(f, "List accounts"),
            AccountCommand::Create => write!(f, "Create new account"),
            AccountCommand::Modify => write!(f, "Modify existing account"),
            AccountCommand::Import => write!(f, "Import existing account from another installation or ACME client"),
            AccountCommand::Delete => write!(f, "Delete (deactivate) account"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum CertificateCommand {
    /// Issue a certificate
    Issue(IssueCommand),
    /// Renew one or all certificates
    Renew(RenewCommand),
    /// List available certificates
    List,
}

impl Display for CertificateCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CertificateCommand::Issue(_) => write!(f, "Issue a new certificate"),
            CertificateCommand::Renew(_) => write!(f, "Renew your certificates"),
            CertificateCommand::List => write!(f, "List available certificates"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum IssuerCommand {
    /// List configured CAs
    List,
    /// Add a new CA
    Add,
    /// Remove a CA
    Remove,
}

impl Display for IssuerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            IssuerCommand::List => write!(f, "List CAs"),
            IssuerCommand::Add => write!(f, "Add CA"),
            IssuerCommand::Remove => write!(f, "Remove CA"),
        }
    }
}

fn is_interactive() -> bool {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    stdin.is_terminal() && stdout.is_terminal() && stderr.is_terminal()
}

async fn process_cli_command(mut cmd: Option<Command>, client: Certonaut, interactive: bool) -> anyhow::Result<()> {
    loop {
        match cmd {
            None => {
                // TODO: Greeting & first-time instructions for new users here
                if interactive {
                    println!("Welcome to {CRATE_NAME}!");
                    let selectable_commands = vec![
                        Command::Issue(IssueCommand::default()),
                        Command::Renew(RenewCommand::default()),
                        Command::InteractiveIssuer,
                        Command::InteractiveCertificate,
                        Command::InteractiveAccount,
                    ];
                    let action = Select::new("What would you like to do?", selectable_commands)
                        .prompt()
                        .context("No action selected");
                    if let Ok(action) = action {
                        cmd = Some(action);
                        continue;
                    }
                    break action.map(|_| ());
                }
                bail!("Welcome! For non-interactive usage, an action (issue, renew) must be specified (a non-interactive terminal was detected, so interactive options have been disabled).");
            }
            Some(Command::InteractiveIssuer) => {
                if interactive {
                    let selectable_commands = vec![IssuerCommand::List, IssuerCommand::Add, IssuerCommand::Remove];
                    let action = Select::new("What would you like to do?", selectable_commands)
                        .prompt()
                        .context("No action selected");
                    if let Ok(action) = action {
                        cmd = Some(Command::Issuer(action));
                        continue;
                    }
                    break action.map(|_| ());
                }
                bail!("This command can only be used interactively (a non-interactive terminal was detected)");
            }
            Some(Command::InteractiveCertificate) => {
                if interactive {
                    let selectable_commands = vec![
                        CertificateCommand::List,
                        CertificateCommand::Issue(IssueCommand::default()),
                        CertificateCommand::Renew(RenewCommand::default()),
                    ];
                    let action = Select::new("What would you like to do?", selectable_commands)
                        .prompt()
                        .context("No action selected");
                    if let Ok(action) = action {
                        cmd = Some(Command::Certificate(action));
                        continue;
                    }
                    break action.map(|_| ());
                }
                bail!("This command can only be used interactively (a non-interactive terminal was detected)");
            }
            Some(Command::InteractiveAccount) => {
                if interactive {
                    let selectable_commands = vec![
                        AccountCommand::List,
                        AccountCommand::Create,
                        AccountCommand::Modify,
                        AccountCommand::Delete,
                        AccountCommand::Import,
                    ];
                    let action = Select::new("What would you like to do?", selectable_commands)
                        .prompt()
                        .context("No action selected");
                    if let Ok(action) = action {
                        cmd = Some(Command::Account(action));
                        continue;
                    }
                    break action.map(|_| ());
                }
                bail!("This command can only be used interactively (a non-interactive terminal was detected)");
            }
            Some(Command::Issue(issue_cmd)) => {
                break process_certificate_command(CertificateCommand::Issue(issue_cmd), client, interactive).await;
            }
            Some(Command::Renew(renew_cmd)) => {
                break process_certificate_command(CertificateCommand::Renew(renew_cmd), client, interactive).await;
            }
            Some(Command::Issuer(issuer_cmd)) => {
                break process_issuer_command(issuer_cmd, client, interactive).await;
            }
            Some(Command::Certificate(certificate_cmd)) => {
                break process_certificate_command(certificate_cmd, client, interactive).await;
            }
            Some(Command::Account(account_cmd)) => {
                break process_account_command(account_cmd, client, interactive).await;
            }
        }
    }
}

async fn process_issuer_command(cmd: IssuerCommand, client: Certonaut, interactive: bool) -> anyhow::Result<()> {
    match cmd {
        IssuerCommand::List => {
            client.print_issuers().await;
            Ok(())
        }
        IssuerCommand::Add => {
            if interactive {
                let mut service = InteractiveService::new(client);
                return service.interactive_add_ca().await;
            }
            todo!("Non-interactive config")
        }
        IssuerCommand::Remove => {
            if interactive {
                let mut service = InteractiveService::new(client);
                return service.interactive_remove_ca().await;
            }
            todo!("Non-interactive config")
        }
    }
}

async fn process_certificate_command(
    cmd: CertificateCommand,
    client: Certonaut,
    interactive: bool,
) -> anyhow::Result<()> {
    match cmd {
        CertificateCommand::Issue(issue_cmd) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                return service.interactive_issuance(issue_cmd).await;
            }
            todo!("Non-interactive issuance")
        }
        CertificateCommand::Renew(_renew_cmd) => {
            let service = RenewService::new(client, interactive);
            service.run().await
        }
        CertificateCommand::List => {
            client.print_certificates();
            Ok(())
        }
    }
}

async fn process_account_command(cmd: AccountCommand, client: Certonaut, interactive: bool) -> anyhow::Result<()> {
    match cmd {
        AccountCommand::List => {
            client.print_accounts().await;
            Ok(())
        }
        AccountCommand::Create => {
            if interactive {
                let mut service = InteractiveService::new(client);
                service.interactive_create_account().await
            } else {
                todo!()
            }
        }
        AccountCommand::Import => {
            todo!()
        }
        AccountCommand::Modify => {
            todo!()
        }
        AccountCommand::Delete => {
            if interactive {
                let mut service = InteractiveService::new(client);
                service.interactive_delete_account().await
            } else {
                todo!()
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = CommandLineArguments::parse();
    let filter = EnvFilter::try_from_env(ENV_FILTER_NAME).unwrap_or_else(|_| {
        EnvFilter::try_from_env("RUST_LOG")
            .unwrap_or_else(|_| EnvFilter::new(if cli.verbose { "certonaut=debug,info" } else { "info" }))
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let interactive = is_interactive() && !cli.noninteractive;
    CONFIG_FILE.set(cli.config).expect("Config file already set");
    let config = config::load()?;
    let client = Certonaut::try_new(config).context("Loading configuration failed")?;
    let result = process_cli_command(cli.command, client, interactive).await;
    if interactive && result.is_err() {
        // Wrap last line to avoid anyhow conflicts with the interactive terminal
        println!();
    }
    result
}
