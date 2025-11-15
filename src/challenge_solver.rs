use crate::acme::object::{AlpnChallenge, DnsChallenge, HttpChallenge, InnerChallenge, Token};
use crate::cli::CommandLineSolverConfiguration;
use crate::config::{
    MagicHttpSolverConfiguration, NullSolverConfiguration, PebbleHttpSolverConfiguration,
    SolverConfiguration, WebrootSolverConfiguration,
};
use crate::crypto::jws::JsonWebKey;
use crate::crypto::{SHA256_LENGTH, sha256};
use crate::dns::solver::acme_dns;
use crate::{Identifier, magic};
use anyhow::{Context, Error, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::{Command, CommandFactory, FromArgMatches, Parser};
use crossterm::style::Stylize;
use inquire::CustomType;
use inquire::validator::Validation;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use url::Url;

impl InnerChallenge {
    pub fn get_type(&self) -> &str {
        match &self {
            InnerChallenge::Http(_) => "http-01",
            InnerChallenge::Dns(_) => "dns-01",
            InnerChallenge::Alpn(_) => "tls-alpn-01",
            InnerChallenge::Unknown => "unknown challenge type",
        }
    }
}

impl HttpChallenge {
    pub fn get_token(&self) -> &Token {
        &self.token
    }

    pub fn get_key_authorization(&self, account_key: &JsonWebKey) -> String {
        get_key_authorization(account_key, &self.token)
    }
}

impl DnsChallenge {
    pub fn get_key_authorization(&self, account_key: &JsonWebKey) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(sha256(
            get_key_authorization(account_key, &self.token).as_bytes(),
        ))
    }
}

impl AlpnChallenge {
    pub fn get_key_authorization(&self, account_key: &JsonWebKey) -> [u8; SHA256_LENGTH] {
        sha256(get_key_authorization(account_key, &self.token).as_bytes())
    }
}

fn get_key_authorization(key: &JsonWebKey, token: &Token) -> String {
    let thumbprint = key.get_acme_thumbprint();
    format!("{token}.{thumbprint}")
}

#[async_trait]
pub trait ChallengeSolver: Send {
    fn long_name(&self) -> &'static str;
    fn short_name(&self) -> &'static str;
    // TODO: Preference sorting in case a solver supports multiple?
    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool;
    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error>;
    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Debug, Default, Clone)]
pub struct NullSolver {}

impl NullSolver {
    pub fn from_config(_config: NullSolverConfiguration) -> Box<Self> {
        Box::new(NullSolver {})
    }
}

#[async_trait]
impl ChallengeSolver for NullSolver {
    fn long_name(&self) -> &'static str {
        "null solver"
    }

    fn short_name(&self) -> &'static str {
        "null"
    }

    fn supports_challenge(&self, _challenge: &InnerChallenge) -> bool {
        true
    }

    async fn deploy_challenge(
        &mut self,
        _jwk: &JsonWebKey,
        _identifier: &Identifier,
        _challenge: InnerChallenge,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct WebrootSolver {
    webroot: PathBuf,
    challenge_file: Option<PathBuf>,
}

impl WebrootSolver {
    pub fn from_config(config: WebrootSolverConfiguration) -> Box<Self> {
        Box::new(WebrootSolver {
            webroot: config.webroot,
            challenge_file: None,
        })
    }

    pub fn challenge_path(&self, token: &Token) -> PathBuf {
        self.webroot
            .join(Path::new(".well-known/acme-challenge/"))
            .join(token.as_str())
    }
}

#[async_trait]
impl ChallengeSolver for WebrootSolver {
    fn long_name(&self) -> &'static str {
        "webroot"
    }

    fn short_name(&self) -> &'static str {
        "webroot"
    }

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Http(_))
    }

    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        _identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        if let InnerChallenge::Http(http_challenge) = challenge {
            let token = http_challenge.get_token();
            let authorization = http_challenge.get_key_authorization(jwk);
            let challenge_path = self.challenge_path(token);
            if let Some(parent) = challenge_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context(format!("Failed to create directory {}", parent.display()))?;
            }
            let mut challenge_file = File::create(&challenge_path).await.context(format!(
                "Failed to create challenge file {}",
                challenge_path.display()
            ))?;
            challenge_file
                .write_all(authorization.as_bytes())
                .await
                .context(format!(
                    "Writing to challenge file {} failed",
                    challenge_path.display()
                ))?;
            self.challenge_file = Some(challenge_path);
            Ok(())
        } else {
            bail!("Unsupported challenge type {}", challenge.get_type())
        }
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        if let Some(path) = self.challenge_file {
            tokio::fs::remove_file(&path).await.context(format!(
                "Failed to remove challenge file {}",
                path.display()
            ))
        } else {
            bail!("No challenge to cleanup")
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpChallengeParameters {
    pub token: Token,
    pub key_authorization: String,
    pub challenge_port: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum SolverCategory {
    Advanced,
    Testing,
    Http,
    Dns,
}

impl Display for SolverCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverCategory::Advanced => write!(f, "ADVANCED"),
            SolverCategory::Testing => write!(f, "TESTING ONLY"),
            SolverCategory::Http => write!(f, "HTTP"),
            SolverCategory::Dns => write!(f, "DNS"),
        }
    }
}

#[async_trait]
pub trait SolverConfigBuilder: Send + Sync {
    fn new() -> Box<Self>
    where
        Self: Sized;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> SolverCategory;
    fn preference(&self) -> usize;
    fn supported(&self, domains: &HashSet<Identifier>) -> bool;
    async fn build_interactive(
        &self,
        domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration>;
    async fn build_from_command_line(
        &self,
        cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration>;
    fn get_command_line(&self) -> Command;
}

impl Display for dyn SolverConfigBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} - {}",
            self.category().to_string().blue(),
            self.name().dark_green(),
            self.description().reset()
        )
    }
}

struct NullSolverBuilder;

#[async_trait]
impl SolverConfigBuilder for NullSolverBuilder {
    fn new() -> Box<Self> {
        Box::new(NullSolverBuilder {})
    }

    fn name(&self) -> &'static str {
        "Nothing"
    }

    fn description(&self) -> &'static str {
        "This solver does not authenticate at all. It can be used when the user has already authorized out-of-band 
with the CA. Will cause failures otherwise."
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Advanced
    }

    fn preference(&self) -> usize {
        100
    }

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        true
    }

    async fn build_interactive(
        &self,
        _domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration> {
        Ok(SolverConfiguration::Null(NullSolverConfiguration {}))
    }

    async fn build_from_command_line(
        &self,
        _cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration> {
        Ok(SolverConfiguration::Null(NullSolverConfiguration {}))
    }

    fn get_command_line(&self) -> Command {
        Command::new("nothing").about(self.description())
    }
}

struct ChallengeTestHttpBuilder;

#[async_trait]
impl SolverConfigBuilder for ChallengeTestHttpBuilder {
    fn new() -> Box<Self> {
        Box::new(ChallengeTestHttpBuilder {})
    }

    fn name(&self) -> &'static str {
        "Pebble HTTP"
    }

    fn description(&self) -> &'static str {
        "Talks to a pebble-challtestsrv to solve HTTP-01 challenges. Only works with the Pebble Test CA."
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Testing
    }

    fn preference(&self) -> usize {
        90
    }

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        cfg!(debug_assertions)
    }

    async fn build_interactive(
        &self,
        _domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration> {
        Ok(SolverConfiguration::PebbleHttp(
            PebbleHttpSolverConfiguration {
                base_url: Url::parse("http://localhost:8055")?,
            },
        ))
    }

    async fn build_from_command_line(
        &self,
        _cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration> {
        Ok(SolverConfiguration::PebbleHttp(
            PebbleHttpSolverConfiguration {
                base_url: Url::parse("http://localhost:8055")?,
            },
        ))
    }

    fn get_command_line(&self) -> Command {
        Command::new("pebble-http").about(self.description())
    }
}

struct MagicHttpBuilder;

/// The "magic" HTTP solver uses eBPF technology to solve HTTP-01 challenges automatically, without requiring any configuration in many cases.
#[derive(Debug, Parser)]
#[command(name = "auto", about)]
struct MagicHttpOptions {
    /// The port the CA validates http-01 challenges on (or the destination port if any NAT is present). Usually 80.
    #[arg(value_parser = clap::value_parser!(u16).range(1..), long)]
    validation_port: Option<u16>,
}

#[async_trait]
impl SolverConfigBuilder for MagicHttpBuilder {
    fn new() -> Box<Self> {
        Box::new(MagicHttpBuilder {})
    }

    fn name(&self) -> &'static str {
        "Automatic / \"magic\""
    }

    fn description(&self) -> &'static str {
        "The \"magic\" HTTP solver uses eBPF technology to solve HTTP-01 challenges automatically, without requiring any configuration in many cases."
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Http
    }

    fn preference(&self) -> usize {
        5
    }

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        magic::is_supported()
    }

    async fn build_interactive(
        &self,
        _domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration> {
        if !magic::is_supported() {
            bail!("The magic solver is not supported by your system");
        }

        println!(
            "Some (non-public) CAs do not adhere to RFC8555 and validate on a port other than port 80."
        );
        println!(
            "This may also apply if you have NAT port-mapped your external port 80 to another internal port on this host."
        );
        println!("If any of the above applies, you can enter the port number here");
        let port =
            CustomType::<u16>::new("Which port number does the CA validate HTTP-01 challenges on?")
                .with_validator(|port: &u16| {
                    Ok(if *port > 0 {
                        Validation::Valid
                    } else {
                        Validation::Invalid("Port 0 is not valid".into())
                    })
                })
                .with_error_message("Must be a port number")
                .with_help_message("Enter the port number, or press ESC to use the default")
                .prompt_skippable()?;
        Ok(SolverConfiguration::MagicHttp(
            MagicHttpSolverConfiguration {
                validation_port: port,
            },
        ))
    }

    async fn build_from_command_line(
        &self,
        cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration> {
        if !magic::is_supported() {
            bail!("The magic solver is not supported by your system");
        }

        let options = MagicHttpOptions::from_arg_matches(&cmd_line_config.matches)?;
        Ok(SolverConfiguration::MagicHttp(
            MagicHttpSolverConfiguration {
                validation_port: options.validation_port,
            },
        ))
    }

    fn get_command_line(&self) -> Command {
        MagicHttpOptions::command()
    }
}

/// Webroot uses your existing webserver to serve a (single) static file that solves the HTTP-01 challenge.
#[derive(Debug, Parser)]
#[command(name = "webroot")]
struct WebrootCommand {
    /// The "webroot" (or "document root") of your existing webserver, from where static files can be served
    webroot: PathBuf,
}

struct WebrootBuilder;

#[async_trait]
impl SolverConfigBuilder for WebrootBuilder {
    fn new() -> Box<Self> {
        Box::new(WebrootBuilder {})
    }

    fn name(&self) -> &'static str {
        "Webroot"
    }

    fn description(&self) -> &'static str {
        "Webroot uses your existing webserver to serve a (single) static file that solves the HTTP-01 challenge. Your webserver must support serving static files from the filesystem."
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Http
    }

    fn preference(&self) -> usize {
        10
    }

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        true
    }

    async fn build_interactive(
        &self,
        _domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration> {
        println!(
            "The webroot solver needs to know from where your webserver serves static files (the \"webroot\" of your webserver)."
        );
        println!(
            "The solver will place a static file in this directory to solve the CA's challenge."
        );
        println!("Please provide the top-level directory from where your domain is served.");
        let webroot = CustomType::<String>::new(
            "Enter the directory path to your webserver's root directory:",
        )
        .with_validator(|path: &String| {
            Ok(match std::fs::exists(path) {
                Ok(true) => Validation::Valid,
                Ok(false) => {
                    Validation::Invalid(format!("Path {path} is not a valid path on-disk").into())
                }
                Err(e) => Validation::Invalid(
                    format!("Failed to determine if {path} exists on-disk: {e:#}").into(),
                ),
            })
        })
        .with_help_message("Enter a directory path")
        .prompt()
        .context("No webroot entered")?;
        let webroot = PathBuf::from(webroot);
        Ok(SolverConfiguration::Webroot(WebrootSolverConfiguration {
            webroot,
        }))
    }

    async fn build_from_command_line(
        &self,
        cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration> {
        let webroot_command = WebrootCommand::from_arg_matches(&cmd_line_config.matches)
            .context("Failed to parse webroot command line")?;
        Ok(SolverConfiguration::Webroot(WebrootSolverConfiguration {
            webroot: webroot_command.webroot,
        }))
    }

    fn get_command_line(&self) -> Command {
        WebrootCommand::command()
    }
}

pub static CHALLENGE_SOLVER_REGISTRY: LazyLock<Vec<Box<dyn SolverConfigBuilder>>> =
    LazyLock::new(|| {
        let mut builders: Vec<Box<dyn SolverConfigBuilder>> = vec![
            NullSolverBuilder::new(),
            ChallengeTestHttpBuilder::new(),
            MagicHttpBuilder::new(),
            WebrootBuilder::new(),
            acme_dns::Builder::new(),
        ];
        builders.sort_by_key(|b| b.preference());
        builders
    });
