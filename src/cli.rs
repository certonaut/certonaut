use crate::acme::object::Identifier;
use crate::challenge_solver::{SolverConfigBuilder, CHALLENGE_SOLVER_REGISTRY};
use crate::config;
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::interactive::InteractiveService;
use crate::renew::RenewService;
use crate::CRATE_NAME;
use crate::{parse_duration, Certonaut};
use anyhow::{bail, Context};
use aws_lc_rs::rsa::KeySize;
use clap::{ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use inquire::Select;
use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use strum::VariantArray;

#[derive(Debug, Parser)]
#[command(version, about, long_about = "")]
pub struct CommandLineArguments {
    /// Path to configuration directory
    #[arg(short, long, env = "CERTONAUT_CONFIG", default_value_os_t = config::get_default_config_directory())]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Shorthand option to enable debug logging (logging can be fine-tuned via `CERTONAUT_LOG` environment variable)
    #[clap(long, short, action)]
    pub verbose: bool,
    /// Force certonaut to disable all interactive prompts, even if a terminal was detected
    #[clap(long, action)]
    pub noninteractive: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Shorthand for 'certificate issue'
    Issue(IssueCommand),
    /// Shorthand for 'certificate renew'
    Renew(RenewCommand),
    /// Create, edit, or view ACME accounts
    #[command(subcommand)]
    Account(AccountCommand),
    /// Issue, edit, or view certificates
    #[command(subcommand, alias = "cert")]
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
pub enum AccountCommand {
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
pub enum CertificateCommand {
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
pub enum IssuerCommand {
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

#[derive(Debug, Parser, Default)]
#[command(
    subcommand_precedence_over_arg = true,
    flatten_help = true,
    subcommand_help_heading = "Solvers"
)]
pub struct IssueCommand {
    /// ID of the CA to use
    #[clap(short, long, global = true)]
    pub ca: Option<String>,
    /// ID of the account to use
    #[clap(short, long, global = true)]
    pub account: Option<String>,
    /// Domain names to include in the certificate
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    pub domains: Option<Vec<String>>,
    /// The display name of the new certificate
    #[clap(long, global = true)]
    pub cert_name: Option<String>,
    #[clap(flatten)]
    pub advanced: AdvancedIssueConfiguration,
    #[clap(skip)]
    pub solver_configuration: Vec<CommandLineSolverConfiguration>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct AdvancedIssueConfiguration {
    /// Type of key to use for the certificate
    #[clap(short, long, global = true)]
    pub key_type: Option<CommandLineKeyType>,
    /// ACME profile to use, if the CA offers ACME profile selection
    #[clap(short, long, global = true)]
    pub profile: Option<String>,
    /// Lifetime of the requested certificate, if supported by the CA
    #[clap(short, long, value_parser = parse_duration, global = true)]
    pub lifetime: Option<Duration>,
    /// Whether to reuse the same private key on each renewal, or rotate the key on each renewal
    #[clap(short, long, global = true)]
    pub reuse_key: bool,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, VariantArray)]
pub enum CommandLineKeyType {
    /// ECDSA with NIST P-256
    #[default]
    P256,
    /// ECDSA with NIST P-384
    P384,
    /// RSA (2048-bit key)
    Rsa2048,
    /// RSA (3072-bit key)
    Rsa3072,
    /// RSA (4096-bit key)
    Rsa4096,
    /// RSA (8192-bit key)
    Rsa8192,
}

impl Display for CommandLineKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enum_value = self.to_possible_value().unwrap(/* Infallible */);
        write!(f, "{}", enum_value.get_help().unwrap(/* Infallible */))
    }
}

impl From<CommandLineKeyType> for KeyType {
    fn from(key_type: CommandLineKeyType) -> Self {
        match key_type {
            CommandLineKeyType::P256 => KeyType::Ecdsa(Curve::P256),
            CommandLineKeyType::P384 => KeyType::Ecdsa(Curve::P384),
            CommandLineKeyType::Rsa2048 => KeyType::Rsa(KeySize::Rsa2048),
            CommandLineKeyType::Rsa3072 => KeyType::Rsa(KeySize::Rsa3072),
            CommandLineKeyType::Rsa4096 => KeyType::Rsa(KeySize::Rsa4096),
            CommandLineKeyType::Rsa8192 => KeyType::Rsa(KeySize::Rsa8192),
        }
    }
}

#[derive(Debug, Args, Default)]
pub struct RenewCommand {}

#[derive(Debug, Args, Clone)]
#[command(subcommand_precedence_over_arg = true)]
pub struct AuthenticatorBaseCommand {
    /// Domain names to include in the certificate
    #[clap(short, long, value_delimiter = ',', num_args = 1, required = true)]
    pub domains: Vec<Identifier>,
}

#[derive(Clone)]
pub struct CommandLineSolverConfiguration {
    pub solver: &'static dyn SolverConfigBuilder,
    pub base: AuthenticatorBaseCommand,
    pub matches: ArgMatches,
}

impl Debug for CommandLineSolverConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandLineSolverConfiguration")
            .field("solver", &self.solver.name())
            .field("base", &self.base)
            .field("matches", &self.matches)
            .finish()
    }
}

pub async fn process_cli_command(
    mut cmd: Option<Command>,
    matches: &ArgMatches,
    client: Certonaut,
    interactive: bool,
) -> anyhow::Result<()> {
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
                break process_certificate_command(CertificateCommand::Issue(issue_cmd), matches, client, interactive)
                    .await;
            }
            Some(Command::Renew(renew_cmd)) => {
                break process_certificate_command(CertificateCommand::Renew(renew_cmd), matches, client, interactive)
                    .await;
            }
            Some(Command::Issuer(issuer_cmd)) => {
                break process_issuer_command(issuer_cmd, client, interactive).await;
            }
            Some(Command::Certificate(certificate_cmd)) => {
                break process_certificate_command(certificate_cmd, matches, client, interactive).await;
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
    matches: &ArgMatches,
    client: Certonaut,
    interactive: bool,
) -> anyhow::Result<()> {
    match cmd {
        CertificateCommand::Issue(issue_cmd) => {
            let issue_cmd = process_issue_cmd(issue_cmd, matches)?;
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

fn process_issue_cmd(mut issue_cmd: IssueCommand, raw_matches: &ArgMatches) -> anyhow::Result<IssueCommand> {
    let mut matches = match raw_matches.subcommand() {
        Some(("issue", matches)) => matches,
        Some(("certificate", matches)) => matches
            .subcommand()
            .map(|(_, matches)| matches)
            .expect("BUG: Too few subcommands"),
        _ => return Ok(issue_cmd),
    };

    let mut solvers = Vec::new();
    while let Some((subcommand_name, subcommand_matches)) = matches.subcommand() {
        let base = AuthenticatorBaseCommand::from_arg_matches(subcommand_matches)?;
        let solver = CHALLENGE_SOLVER_REGISTRY
            .iter()
            .find(|solver| solver.get_command_line().get_name() == subcommand_name)
            .expect("BUG: Solver subcommand not found");
        let solver_config = CommandLineSolverConfiguration {
            solver: solver.as_ref(),
            base,
            matches: subcommand_matches.clone(),
        };
        solvers.push(solver_config);
        matches = subcommand_matches;
    }

    if !solvers.is_empty() && issue_cmd.domains.is_some() {
        bail!("Can not specify both global domains and per-solver domains. Use --domains after giving the solver.",);
    }

    issue_cmd.solver_configuration = solvers;
    Ok(issue_cmd)
}

// Helpers to avoid infinite recursion during clap's --help parsing
const MAX_SOLVER_SUBCOMMAND_LENGTH: usize = 100;
static SOLVER_RECURSION_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Helper to recursively add solver subcommands to an existing solver subcommand, to allow for a chain of solvers
fn recursive_solver_subcommands(subcommand: clap::Command) -> clap::Command {
    if SOLVER_RECURSION_COUNTER.fetch_add(1, Ordering::SeqCst) > MAX_SOLVER_SUBCOMMAND_LENGTH {
        return subcommand;
    };

    subcommand.subcommands(
        CHALLENGE_SOLVER_REGISTRY
            .iter()
            .map(|solver| AuthenticatorBaseCommand::augment_args(solver.get_command_line()).hide(true))
            .map(|subcommand| subcommand.defer(recursive_solver_subcommands)),
    )
}

#[allow(clippy::missing_panics_doc)]
pub fn setup_command_line() -> Result<(CommandLineArguments, ArgMatches), clap::Error> {
    let mut main_cmd = CommandLineArguments::command();
    let issue_cmd_ref = main_cmd
        .get_subcommands_mut()
        .find(|sc| sc.get_name() == "certificate")
        .and_then(|sc| sc.get_subcommands_mut().find(|sc| sc.get_name() == "issue"))
        .expect("BUG: No certificate issue subcommand found");
    let issue_cmd = std::mem::replace(issue_cmd_ref, clap::Command::new("placeholder"));
    let issue_cmd = issue_cmd.subcommands(
        CHALLENGE_SOLVER_REGISTRY
            .iter()
            .map(|solver_builder| AuthenticatorBaseCommand::augment_args(solver_builder.get_command_line()))
            .map(|subcommand| subcommand.defer(recursive_solver_subcommands)),
    );
    *issue_cmd_ref = issue_cmd.clone();
    let issue_cmd_ref_alias = main_cmd
        .get_subcommands_mut()
        .find(|sc| sc.get_name() == "issue")
        .expect("BUG: No issue alias subcommand found");
    *issue_cmd_ref_alias = issue_cmd.about("Shorthand for 'certificate issue'");

    let matches = main_cmd.get_matches();
    let command_line = CommandLineArguments::from_arg_matches(&matches)?;
    Ok((command_line, matches))
}
