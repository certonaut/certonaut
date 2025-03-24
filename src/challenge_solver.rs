use crate::acme::object::{InnerChallenge, Token};
use crate::cli::CommandLineSolverConfiguration;
use crate::config::{
    MagicHttpSolverConfiguration, NullSolverConfiguration, PebbleHttpSolverConfiguration,
    SolverConfiguration, WebrootSolverConfiguration,
};
use crate::crypto::jws::JsonWebKey;
use crate::{acme, config, magic};
use anyhow::{bail, Context, Error};
use async_trait::async_trait;
use clap::{value_parser, Arg, Command, CommandFactory, FromArgMatches, Parser};
use inquire::validator::Validation;
use inquire::CustomType;
use std::collections::HashSet;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub trait KeyAuthorization {
    fn get_type(&self) -> &str;
    fn get_token(&self) -> &Token;
    fn get_key_authorization(&self, account_key: &JsonWebKey) -> String;
}

impl KeyAuthorization for InnerChallenge {
    fn get_type(&self) -> &str {
        match &self {
            InnerChallenge::Http(_) => "http-01",
            InnerChallenge::Dns(_) => "dns-01",
            InnerChallenge::Alpn(_) => "tls-alpn-01",
            InnerChallenge::Unknown => "unknown challenge type",
        }
    }

    fn get_token(&self) -> &Token {
        match &self {
            InnerChallenge::Http(http) => &http.token,
            InnerChallenge::Dns(dns) => &dns.token,
            InnerChallenge::Alpn(alpn) => &alpn.token,
            InnerChallenge::Unknown => panic!("Unknown challenge cannot be authorized"),
        }
    }

    fn get_key_authorization(&self, account_key: &JsonWebKey) -> String {
        let token = self.get_token();
        get_key_authorization(account_key, token)
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
        identifier: &acme::object::Identifier,
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
        _identifier: &acme::object::Identifier,
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
        _identifier: &acme::object::Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        let token = challenge.get_token();
        let authorization = challenge.get_key_authorization(jwk);
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
}

impl Display for SolverCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverCategory::Advanced => write!(f, "ADVANCED"),
            SolverCategory::Testing => write!(f, "TESTING ONLY"),
            SolverCategory::Http => write!(f, "HTTP"),
        }
    }
}

pub trait SolverConfigBuilder: Send + Sync {
    fn new() -> Box<Self>
    where
        Self: Sized;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> SolverCategory;
    fn preference(&self) -> usize;
    fn supported(&self, domains: &HashSet<config::Identifier>) -> bool;
    fn build_interactive(
        &self,
        domains: HashSet<config::Identifier>,
    ) -> anyhow::Result<DomainsWithSolverConfiguration>;
    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<DomainsWithSolverConfiguration>;
    fn get_command_line(&self) -> Command;
}

#[derive(Debug)]
pub struct DomainsWithSolverConfiguration {
    pub domains: HashSet<config::Identifier>,
    pub config: SolverConfiguration,
    pub solver_name: Option<String>,
}

struct NullSolverBuilder;

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

    fn supported(&self, _domains: &HashSet<config::Identifier>) -> bool {
        true
    }

    fn build_interactive(
        &self,
        domains: HashSet<config::Identifier>,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        Ok(DomainsWithSolverConfiguration {
            domains,
            config: SolverConfiguration::Null(NullSolverConfiguration {}),
            solver_name: None,
        })
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        Ok(DomainsWithSolverConfiguration {
            domains: cmd_line_config.base.domains.into_iter().collect(),
            config: SolverConfiguration::Null(NullSolverConfiguration {}),
            solver_name: None,
        })
    }

    fn get_command_line(&self) -> Command {
        Command::new("nothing").about(self.description())
    }
}

struct ChallengeTestHttpBuilder;

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

    fn supported(&self, _domains: &HashSet<config::Identifier>) -> bool {
        cfg!(debug_assertions)
    }

    fn build_interactive(
        &self,
        domains: HashSet<config::Identifier>,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        Ok(DomainsWithSolverConfiguration {
            domains,
            config: SolverConfiguration::PebbleHttp(PebbleHttpSolverConfiguration {}),
            solver_name: None,
        })
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        Ok(DomainsWithSolverConfiguration {
            domains: cmd_line_config.base.domains.into_iter().collect(),
            config: SolverConfiguration::PebbleHttp(PebbleHttpSolverConfiguration {}),
            solver_name: None,
        })
    }

    fn get_command_line(&self) -> Command {
        Command::new("pebble-http").about(self.description())
    }
}

struct MagicHttpBuilder;

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

    fn supported(&self, _domains: &HashSet<config::Identifier>) -> bool {
        magic::is_supported()
    }

    fn build_interactive(
        &self,
        domains: HashSet<config::Identifier>,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
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
        Ok(DomainsWithSolverConfiguration {
            domains,
            config: SolverConfiguration::MagicHttp(MagicHttpSolverConfiguration {
                validation_port: port,
            }),
            solver_name: None,
        })
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        if !magic::is_supported() {
            bail!("The magic solver is not supported by your system");
        }

        let validation_port = cmd_line_config
            .matches
            .get_one::<u16>("validation_port")
            .copied();
        if matches!(validation_port, Some(0)) {
            bail!("Port 0 is not valid");
        }
        Ok(DomainsWithSolverConfiguration {
            domains: cmd_line_config.base.domains.into_iter().collect(),
            config: SolverConfiguration::MagicHttp(MagicHttpSolverConfiguration {
                validation_port,
            }),
            solver_name: None,
        })
    }

    fn get_command_line(&self) -> Command {
        // TODO: help text
        Command::new("auto").about(self.description()).arg(
            Arg::new("validation_port")
                .long("validation-port")
                .value_parser(value_parser!(u16)),
        )
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

    fn supported(&self, _domains: &HashSet<config::Identifier>) -> bool {
        true
    }

    fn build_interactive(
        &self,
        domains: HashSet<config::Identifier>,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        println!(
            "The webroot solver needs to know from where your webserver serves static files (the \"webroot\" of your webserver)."
        );
        println!(
            "The solver will place a static file in this directory to solve the CA's challenge."
        );
        println!(
            "Please provide the top-level directory from where your domain(s) (i.e. https://example.com/) is/are served."
        );
        println!("If you have more than one webroot, please use the multi-solver option instead.");
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
        Ok(DomainsWithSolverConfiguration {
            domains,
            config: SolverConfiguration::Webroot(WebrootSolverConfiguration { webroot }),
            solver_name: None,
        })
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<DomainsWithSolverConfiguration> {
        let webroot_command = WebrootCommand::from_arg_matches(&cmd_line_config.matches)
            .context("Failed to parse webroot command line")?;
        Ok(DomainsWithSolverConfiguration {
            domains: cmd_line_config.base.domains.into_iter().collect(),
            config: SolverConfiguration::Webroot(WebrootSolverConfiguration {
                webroot: webroot_command.webroot,
            }),
            solver_name: None,
        })
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
        ];
        builders.sort_by_key(|b| b.preference());
        builders
    });
