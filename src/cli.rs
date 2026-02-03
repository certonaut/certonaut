use crate::challenge_solver::{CHALLENGE_SOLVER_REGISTRY, SolverConfigBuilder};
use crate::config;
use crate::config::ConfigBackend;
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::interactive::service::InteractiveService;
use crate::non_interactive::NonInteractiveService;
use crate::renew::RenewService;
use crate::time::parse_duration;
use crate::{CRATE_NAME, Identifier};
use crate::{Certonaut, RevocationReason};
use anyhow::{Context, bail};
use aws_lc_rs::rsa::KeySize;
use clap::{ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use inquire::Select;
use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use strum::VariantArray;
use url::Url;

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
    #[clap(alias = "non-interactive")]
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
    /// Troubleshooting and test actions
    #[command(subcommand)]
    Debug(DebugCommand),
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
            Command::Issue(_issue) => {
                write!(f, "{}", CertificateCommand::Issue(IssueCommand::default()))
            }
            Command::Renew(_renew) => {
                write!(f, "{}", CertificateCommand::Renew(RenewCommand::default()))
            }
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
    Create(AccountCreateCommand),
    /// Import an existing account from another computer or another ACME client software
    Import(AccountImportCommand),
    // /// Change settings of an existing account
    // Modify,
    /// Delete and deactivate an account
    Delete(AccountDeleteCommand),
}

impl Display for AccountCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AccountCommand::List => write!(f, "List accounts"),
            AccountCommand::Create(_) => write!(f, "Create new account"),
            // AccountCommand::Modify => write!(f, "Modify existing account"),
            AccountCommand::Import(_) => write!(
                f,
                "Import existing account from another installation or ACME client"
            ),
            AccountCommand::Delete(_) => write!(f, "Delete (deactivate) account"),
        }
    }
}

#[derive(Debug, Args, Default)]
pub struct AccountCreateCommand {
    /// Display name of the new account
    #[arg(short, long)]
    pub account_name: Option<String>,
    /// Unique identifier of the new account
    #[arg(long = "id")]
    pub account_id: Option<String>,
    /// Identifier of the certificate authority where to create the account
    #[arg(short, long = "ca")]
    pub ca_identifier: Option<String>,
    /// Contact address(es) to provide to the CA
    #[arg(long)]
    pub contact: Vec<String>,
    /// Set to indicate that you agree to the CA's terms of service
    #[arg(long)]
    pub terms_of_service_agreed: bool,
    /// The `EAB_KID` (Key ID) for ACME External Account Binding (EAB)
    #[arg(long = "eab-kid", requires = "external_account_hmac_key")]
    pub external_account_kid: Option<String>,
    /// The `EAB_HMAC_KEY` (HMAC Key) for ACME External Account Binding (EAB)
    #[arg(long = "eab-hmac-key", requires = "external_account_kid")]
    pub external_account_hmac_key: Option<String>,
}

#[derive(Debug, Args, Default)]
pub struct AccountImportCommand {
    /// Display name of the new account
    #[arg(short, long)]
    pub account_name: Option<String>,
    /// Unique identifier of the new account
    #[arg(long = "id")]
    pub account_id: Option<String>,
    /// Identifier of the certificate authority where to create the account
    #[arg(short, long = "ca")]
    pub ca_identifier: Option<String>,
    /// File path for the existing account key (PEM format)
    #[arg(short, long)]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Args, Default)]
pub struct AccountDeleteCommand {
    /// Unique identifier of the new account
    #[arg(long = "id")]
    pub account_id: Option<String>,
    /// Identifier of the certificate authority to which the account belongs
    #[arg(short, long = "ca")]
    pub ca_identifier: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum CertificateCommand {
    /// Issue a certificate
    Issue(IssueCommand),
    /// Renew one or all certificates
    Renew(RenewCommand),
    /// List available certificates
    List,
    /// Change the renewal configuration of an existing certificate
    Modify(CertificateModifyCommand),
    /// Revoke an existing certificate
    Revoke(RevokeCommand),
}

impl Display for CertificateCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CertificateCommand::Issue(_) => write!(f, "Issue a new certificate"),
            CertificateCommand::Renew(_) => write!(f, "Renew your certificates"),
            CertificateCommand::List => write!(f, "List available certificates"),
            CertificateCommand::Modify(_) => write!(f, "Modify existing certificate"),
            CertificateCommand::Revoke(_) => write!(f, "Revoke an existing certificate"),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum IssuerCommand {
    /// List configured CAs
    List,
    /// Add a new CA
    Add(IssuerAddCommand),
    /// Remove a CA
    Remove(IssuerRemoveCommand),
}

impl Display for IssuerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            IssuerCommand::List => write!(f, "List CAs"),
            IssuerCommand::Add(_) => write!(f, "Add CA"),
            IssuerCommand::Remove(_) => write!(f, "Remove CA"),
        }
    }
}

#[derive(Debug, Args, Default)]
pub struct IssuerAddCommand {
    /// Name of the new Certificate Authority
    #[arg(short, long)]
    pub name: Option<String>,
    /// Unique identifier of the new Certificate Authority
    #[arg(long)]
    pub id: Option<String>,
    /// ACME directory URL of the CA
    #[arg[short = 'd', long]]
    pub acme_directory: Option<Url>,
    /// Set to indicate a public CA
    #[arg(short, long)]
    pub public: bool,
    /// Set to indicate this CA is used for testing
    #[arg(short, long)]
    pub testing: bool,
    /// Set to indicate this CA should be used as default from now on
    #[arg(long)]
    pub default: bool,
}

#[derive(Debug, Args, Default)]
pub struct IssuerRemoveCommand {
    /// Identifier of the Certificate Authority to remove
    #[arg(long)]
    pub id: Option<String>,
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
    // TODO: Consider removing the domains here as they're really just confusing for users (they conflict with per-solver domains)
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    pub domains: Option<Vec<Identifier>>,
    /// The display name of the new certificate
    #[clap(long, global = true)]
    pub cert_name: Option<String>,
    #[clap(flatten)]
    pub advanced: AdvancedIssueConfiguration,
    /// Script to run to install the certificate
    #[clap(short, long = "install", global = true)]
    pub install_script: Option<String>,
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
    /// The name of the issuer of the last certificate, if the CA offers multiple chains
    #[clap(long, global = true)]
    pub preferred_chain: Option<String>,
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
pub struct RenewCommand {
    /// Optional: The ID of a cert to be renewed. If not given, all certificates will be renewed.
    #[clap(long = "cert")]
    pub cert_id: Option<String>,
    /// Renew the specified certificate early, ignoring the normal renewal schedule. Can only be used for a single certificate.
    #[clap(long, requires = "cert_id")]
    pub renew_early: bool,
}

#[derive(Debug, Args, Clone)]
#[command(subcommand_precedence_over_arg = true)]
pub struct AuthenticatorBaseCommand {
    /// Domain names to include in the certificate
    #[clap(short, long, value_delimiter = ',', num_args = 1, required = true)]
    pub domains: Vec<Identifier>,
    /// Custom name for this solver
    #[clap(long)]
    pub name: Option<String>,
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

#[derive(Debug, Args, Default)]
pub struct CertificateModifyCommand {
    /// The identifier of the certificate to edit
    #[clap(long = "cert", global = true)]
    pub cert_id: Option<String>,
    #[clap(flatten)]
    pub new_config: IssueCommand,
}

#[derive(Debug, Args, Default)]
pub struct RevokeCommand {
    /// The identifier of the certificate to revoke
    #[clap(long = "cert")]
    pub cert_id: Option<String>,
    /// The reason code for which this certificate is revoked (optional).
    ///
    /// These codes may differ in their semantics from CA to CA. Not all CAs support all reason codes.
    /// For all reason codes, consult the CA's documentation to determine when they are appropriate.
    #[clap(long)]
    pub reason: Option<RevocationReason>,
}

#[derive(Debug, Subcommand, Default)]
pub enum DebugCommand {
    /// Do nothing.
    #[default]
    #[clap(hide = true)]
    Nothing,
    /// Retrieve an order from the CA and display it
    ShowOrder(DebugShowOrderCommand),
    /// Retrieve an authorization from the CA and display it
    ShowAuthorization(DebugShowAuthorizationCommand),
    /// Retrieve a challenge from the CA and display it
    ShowChallenge(DebugShowChallengeCommand),
    /// Deactivate all authorizations for an order
    DeactivateAuthorizations(DebugDeactivateAuthorizationCommand),
}

#[derive(Debug, Args)]
pub struct DebugCommonArgs {
    /// The CA for which to perform the debug action
    #[clap(short, long)]
    pub ca: String,
    /// The account to use for the debug action. Mandatory if more than one account exists for the specified CA.
    #[clap(short, long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct DebugShowOrderCommand {
    #[clap(flatten)]
    pub common: DebugCommonArgs,
    /// The order URL
    #[clap(short = 'u', long)]
    pub order_url: Url,
}

#[derive(Debug, Args)]
pub struct DebugShowChallengeCommand {
    #[clap(flatten)]
    pub common: DebugCommonArgs,
    /// The challenge URL
    #[clap(short = 'u', long)]
    pub challenge_url: Url,
}

#[derive(Debug, Args)]
pub struct DebugShowAuthorizationCommand {
    #[clap(flatten)]
    pub common: DebugCommonArgs,
    /// The authorization URL
    #[clap(short = 'u', long)]
    pub authorization_url: Url,
}

#[derive(Debug, Args)]
pub struct DebugDeactivateAuthorizationCommand {
    #[clap(flatten)]
    pub common: DebugCommonArgs,
    /// The order URL
    #[clap(short = 'u', long)]
    pub order_url: Url,
}

pub async fn handle_cli_command<CB: ConfigBackend + Send + Sync + 'static>(
    mut cmd: Option<Command>,
    matches: &ArgMatches,
    client: Certonaut<CB>,
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
                bail!(
                    "Welcome! For non-interactive usage, an action (issue, renew) must be specified (a non-interactive terminal was detected, so interactive options have been disabled)."
                );
            }
            Some(Command::InteractiveIssuer) => {
                if interactive {
                    let selectable_commands = vec![
                        IssuerCommand::List,
                        IssuerCommand::Add(IssuerAddCommand::default()),
                        IssuerCommand::Remove(IssuerRemoveCommand::default()),
                    ];
                    let action = Select::new("What would you like to do?", selectable_commands)
                        .prompt()
                        .context("No action selected");
                    if let Ok(action) = action {
                        cmd = Some(Command::Issuer(action));
                        continue;
                    }
                    break action.map(|_| ());
                }
                bail!(
                    "This command can only be used interactively (a non-interactive terminal was detected)"
                );
            }
            Some(Command::InteractiveCertificate) => {
                if interactive {
                    let selectable_commands = vec![
                        CertificateCommand::List,
                        CertificateCommand::Issue(IssueCommand::default()),
                        CertificateCommand::Renew(RenewCommand::default()),
                        CertificateCommand::Modify(CertificateModifyCommand::default()),
                        CertificateCommand::Revoke(RevokeCommand::default()),
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
                bail!(
                    "This command can only be used interactively (a non-interactive terminal was detected)"
                );
            }
            Some(Command::InteractiveAccount) => {
                if interactive {
                    let selectable_commands = vec![
                        AccountCommand::List,
                        AccountCommand::Create(AccountCreateCommand::default()),
                        // AccountCommand::Modify,
                        AccountCommand::Delete(AccountDeleteCommand::default()),
                        AccountCommand::Import(AccountImportCommand::default()),
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
                bail!(
                    "This command can only be used interactively (a non-interactive terminal was detected)"
                );
            }
            Some(Command::Issue(issue_cmd)) => {
                break handle_certificate_command(
                    CertificateCommand::Issue(issue_cmd),
                    matches,
                    client,
                    interactive,
                )
                .await;
            }
            Some(Command::Renew(renew_cmd)) => {
                break handle_certificate_command(
                    CertificateCommand::Renew(renew_cmd),
                    matches,
                    client,
                    interactive,
                )
                .await;
            }
            Some(Command::Issuer(issuer_cmd)) => {
                break handle_issuer_command(issuer_cmd, client, interactive).await;
            }
            Some(Command::Certificate(certificate_cmd)) => {
                break handle_certificate_command(certificate_cmd, matches, client, interactive)
                    .await;
            }
            Some(Command::Account(account_cmd)) => {
                break handle_account_command(account_cmd, client, interactive).await;
            }
            Some(Command::Debug(debug_cmd)) => {
                break handle_debug_command(debug_cmd, client, interactive).await;
            }
        }
    }
}

async fn handle_issuer_command<CB: ConfigBackend + Send + Sync + 'static>(
    cmd: IssuerCommand,
    client: Certonaut<CB>,
    interactive: bool,
) -> anyhow::Result<()> {
    match cmd {
        IssuerCommand::List => {
            client.print_issuers().await;
            Ok(())
        }
        IssuerCommand::Add(add) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                // TODO: Honor add command
                return service.interactive_add_ca().await;
            }
            let mut service = NonInteractiveService::new(client);
            service.add_new_ca(add).await
        }
        IssuerCommand::Remove(remove) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                // TODO: Honor remove command
                return service.interactive_remove_ca().await;
            }
            let mut service = NonInteractiveService::new(client);
            service.remove_ca(remove)
        }
    }
}

async fn handle_certificate_command<CB: ConfigBackend + Send + Sync + 'static>(
    cmd: CertificateCommand,
    matches: &ArgMatches,
    client: Certonaut<CB>,
    interactive: bool,
) -> anyhow::Result<()> {
    match cmd {
        CertificateCommand::Issue(issue_cmd) => {
            let issue_cmd = enhance_issue_cmd(issue_cmd, matches)?;
            if interactive {
                let mut service = InteractiveService::new(client);
                service.interactive_issuance(issue_cmd).await
            } else {
                let mut service = NonInteractiveService::new(client);
                service.noninteractive_issuance(issue_cmd).await
            }
        }
        CertificateCommand::Renew(renew_cmd) => {
            let service = RenewService::new(client, interactive);
            match renew_cmd.cert_id {
                None => service.renew_all().await,
                Some(cert_id) => {
                    service
                        .renew_single_cert(cert_id, renew_cmd.renew_early)
                        .await
                }
            }
        }
        CertificateCommand::List => {
            client.print_certificates();
            Ok(())
        }
        CertificateCommand::Modify(mut modify) => {
            modify.new_config = enhance_issue_cmd(modify.new_config, matches)?;
            if interactive {
                let mut service = InteractiveService::new(client);
                service.interactive_modify_cert_configuration(modify).await
            } else {
                let mut service = NonInteractiveService::new(client);
                service.modify_cert_config(modify).await
            }
        }
        CertificateCommand::Revoke(revoke) => {
            if interactive {
                let service = InteractiveService::new(client);
                service.interactive_revoke_certificate(revoke).await
            } else {
                let service = NonInteractiveService::new(client);
                service.revoke_certificate(revoke).await
            }
        }
    }
}

async fn handle_account_command<CB: ConfigBackend + Send + Sync + 'static>(
    cmd: AccountCommand,
    client: Certonaut<CB>,
    interactive: bool,
) -> anyhow::Result<()> {
    match cmd {
        AccountCommand::List => {
            client.print_accounts().await;
            Ok(())
        }
        AccountCommand::Create(create) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                // TODO: Honor create command
                service.interactive_create_account().await
            } else {
                let mut service = NonInteractiveService::new(client);
                service.create_account(create).await
            }
        }
        AccountCommand::Import(import) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                // TODO: Honor create command
                service.interactive_import_account(import).await
            } else {
                let mut service = NonInteractiveService::new(client);
                service.import_account(import).await
            }
        }
        // AccountCommand::Modify => {
        //     todo!()
        // }
        AccountCommand::Delete(delete) => {
            if interactive {
                let mut service = InteractiveService::new(client);
                // TODO: Honor delete command
                service.interactive_delete_account().await
            } else {
                let mut service = NonInteractiveService::new(client);
                service.delete_account(delete).await
            }
        }
    }
}

async fn handle_debug_command<CB: ConfigBackend + Send + Sync + 'static>(
    cmd: DebugCommand,
    client: Certonaut<CB>,
    _interactive: bool,
) -> anyhow::Result<()> {
    let service = NonInteractiveService::new(client);
    match cmd {
        DebugCommand::Nothing => Ok(()),
        DebugCommand::ShowOrder(cmd) => service.debug_show_order(cmd).await,
        DebugCommand::ShowAuthorization(cmd) => service.debug_show_authorization(cmd).await,
        DebugCommand::ShowChallenge(cmd) => service.debug_show_challenge(cmd).await,
        DebugCommand::DeactivateAuthorizations(cmd) => {
            service.debug_deactivate_authorization(cmd).await
        }
    }
}

/// Extend a derive-based `IssueCommand` with dynamic information from clap `ArgMatches`
fn enhance_issue_cmd(
    mut issue_cmd: IssueCommand,
    raw_matches: &ArgMatches,
) -> anyhow::Result<IssueCommand> {
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
        bail!(
            "Can not specify both global domains and per-solver domains. Use --domains after giving the solver.",
        );
    }

    issue_cmd.solver_configuration = solvers;
    Ok(issue_cmd)
}

// Helpers to avoid infinite recursion during clap's --help parsing
const MAX_SOLVER_SUBCOMMAND_LENGTH: usize = 100;
static SOLVER_RECURSION_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Helper to recursively add solver subcommands to an existing solver subcommand, to allow for a chain of solvers
fn recursive_solver_subcommands(subcommand: clap::Command) -> clap::Command {
    if SOLVER_RECURSION_COUNTER.fetch_add(1, Ordering::Relaxed) > MAX_SOLVER_SUBCOMMAND_LENGTH {
        return subcommand;
    }

    subcommand.subcommands(
        CHALLENGE_SOLVER_REGISTRY
            .iter()
            .map(|solver| {
                AuthenticatorBaseCommand::augment_args(solver.get_command_line()).hide(true)
            })
            .map(|subcommand| subcommand.defer(recursive_solver_subcommands)),
    )
}

/// Initialize the clap command line. Most of the command-line is pre-initialized by clap's derive API,
/// but we have some custom tweaks that use clap's builder API as well. This function instantiates both
/// and parses the process command line.
///
/// # Returns
///
/// The parsed command line (derive API) and `ArgMatches` (builder API), or an error if the user specified
/// invalid arguments.
#[allow(clippy::missing_panics_doc)]
pub fn setup_command_line() -> Result<(CommandLineArguments, ArgMatches), clap::Error> {
    let main_cmd = build_main_command();
    let matches = main_cmd.get_matches();
    let command_line = CommandLineArguments::from_arg_matches(&matches)?;
    Ok((command_line, matches))
}

fn build_main_command() -> clap::Command {
    fn extend_command_with_solver_chain(cmd: clap::Command) -> clap::Command {
        cmd.subcommands(
            CHALLENGE_SOLVER_REGISTRY
                .iter()
                .map(|solver_builder| {
                    AuthenticatorBaseCommand::augment_args(solver_builder.get_command_line())
                })
                .map(|subcommand| subcommand.defer(recursive_solver_subcommands)),
        )
    }

    // Fixup the IssueCommand: We want to extend it using the builder API.
    // This is a bit annoying in clap's current design.
    let mut main_cmd = CommandLineArguments::command();
    let issue_cmd_ref = main_cmd
        .get_subcommands_mut()
        .find(|sc| sc.get_name() == "certificate")
        .and_then(|sc| sc.get_subcommands_mut().find(|sc| sc.get_name() == "issue"))
        .expect("BUG: No certificate issue subcommand found");
    let issue_cmd = std::mem::replace(issue_cmd_ref, clap::Command::new("placeholder"));
    let issue_cmd = extend_command_with_solver_chain(issue_cmd);
    *issue_cmd_ref = issue_cmd.clone();
    let issue_cmd_ref_alias = main_cmd
        .get_subcommands_mut()
        .find(|sc| sc.get_name() == "issue")
        .expect("BUG: No issue alias subcommand found");
    *issue_cmd_ref_alias = issue_cmd.about("Shorthand for 'certificate issue'");

    let modify_cmd_ref = main_cmd
        .get_subcommands_mut()
        .find(|sc| sc.get_name() == "certificate")
        .and_then(|sc| {
            sc.get_subcommands_mut()
                .find(|sc| sc.get_name() == "modify")
        })
        .expect("BUG: No certificate modify subcommand found");
    let modify_cmd = std::mem::replace(modify_cmd_ref, clap::Command::new("placeholder"));
    *modify_cmd_ref = extend_command_with_solver_chain(modify_cmd);
    main_cmd
}

#[cfg(test)]
mod tests {
    use crate::cli::build_main_command;

    #[test]
    fn validate_clap_args() {
        let cmd = build_main_command();
        cmd.debug_assert();
    }
}
