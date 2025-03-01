use crate::acme::object::{Identifier, InnerChallenge, Token};
use crate::cli::{CommandLineSolverConfiguration, IssueCommand};
use crate::config::{
    MagicHttpSolverConfiguration, NullSolverConfiguration, PebbleHttpSolverConfiguration, SolverConfiguration,
};
use crate::crypto::jws::JsonWebKey;
use crate::{magic, AcmeIssuerWithAccount, Authorizer};
use anyhow::Error;
use async_trait::async_trait;
use clap::{value_parser, Arg, Command};
use crossterm::style::Stylize;
use inquire::validator::Validation;
use inquire::CustomType;
use itertools::Itertools;
use std::collections::HashSet;
use std::fmt::Display;
use std::sync::LazyLock;

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
    fn config(&self) -> SolverConfiguration;
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

    fn config(&self) -> SolverConfiguration {
        SolverConfiguration::Null(NullSolverConfiguration {})
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
    fn supported(&self, domains: &HashSet<Identifier>) -> bool;
    fn build_interactive(
        &self,
        issuer: &AcmeIssuerWithAccount,
        issue_command: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration>;
    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<BuiltSolverConfiguration>;
    fn get_command_line(&self) -> Command;
}

#[derive(Debug)]
pub enum BuiltSolverConfiguration {
    SingleConfig((HashSet<Identifier>, SolverConfiguration)),
    MultipleConfigs(Vec<Authorizer>),
}

impl From<(HashSet<Identifier>, SolverConfiguration)> for BuiltSolverConfiguration {
    fn from(value: (HashSet<Identifier>, SolverConfiguration)) -> Self {
        Self::SingleConfig(value)
    }
}

impl From<Vec<Authorizer>> for BuiltSolverConfiguration {
    fn from(value: Vec<Authorizer>) -> Self {
        Self::MultipleConfigs(value)
    }
}

impl TryInto<Vec<Authorizer>> for BuiltSolverConfiguration {
    type Error = Error;

    fn try_into(self) -> Result<Vec<Authorizer>, Self::Error> {
        Ok(match self {
            BuiltSolverConfiguration::SingleConfig((domains, config)) => {
                let mut authorizers = Vec::with_capacity(domains.len());
                for domain in domains.into_iter().sorted() {
                    authorizers.push(Authorizer::new_boxed(domain, None, config.clone().to_solver()?));
                }
                authorizers
            }
            BuiltSolverConfiguration::MultipleConfigs(authorizer) => authorizer,
        })
    }
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

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        true
    }

    fn build_interactive(
        &self,
        _issuer: &AcmeIssuerWithAccount,
        _issue_command: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        Ok((domains, SolverConfiguration::Null(NullSolverConfiguration {})).into())
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        Ok((
            cmd_line_config.base.domains.into_iter().collect(),
            SolverConfiguration::Null(NullSolverConfiguration {}),
        )
            .into())
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

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        cfg!(debug_assertions)
    }

    fn build_interactive(
        &self,
        _issuer: &AcmeIssuerWithAccount,
        _issue_command: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        Ok((
            domains,
            SolverConfiguration::PebbleHttp(PebbleHttpSolverConfiguration {}),
        )
            .into())
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        Ok((
            cmd_line_config.base.domains.into_iter().collect(),
            SolverConfiguration::PebbleHttp(PebbleHttpSolverConfiguration {}),
        )
            .into())
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

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        magic::is_supported()
    }

    fn build_interactive(
        &self,
        issuer: &AcmeIssuerWithAccount,
        _issue_command: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        let custom_port = if issuer.issuer.config.public {
            // Public CA's always adhere to RFC8555 and validate on port 80
            None
        } else {
            let ca_name = issuer.issuer.config.name.clone().green();
            println!("Non-public CA's such as {ca_name} sometimes do not adhere to RFC8555 and validate on a port other than port 80.");
            println!("If this is the case for {ca_name}, you can enter the port number here");
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
                .prompt_skippable()?
        };
        Ok((
            domains,
            SolverConfiguration::MagicHttp(MagicHttpSolverConfiguration {
                validation_port: custom_port,
            }),
        )
            .into())
    }

    fn build_from_command_line(
        &self,
        cmd_line_config: CommandLineSolverConfiguration,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        let validation_port = cmd_line_config
            .matches
            .get_one::<u16>("validation_port")
            .map(|port| *port);
        Ok((
            cmd_line_config.base.domains.into_iter().collect(),
            SolverConfiguration::MagicHttp(MagicHttpSolverConfiguration { validation_port }),
        )
            .into())
    }

    fn get_command_line(&self) -> Command {
        Command::new("auto").about(self.description()).arg(
            Arg::new("validation_port")
                .short('p')
                .long("validation-port")
                .value_parser(value_parser!(u16)),
        )
    }
}

pub static CHALLENGE_SOLVER_REGISTRY: LazyLock<Vec<Box<dyn SolverConfigBuilder>>> = LazyLock::new(|| {
    let mut builders: Vec<Box<dyn SolverConfigBuilder>> = vec![
        NullSolverBuilder::new(),
        ChallengeTestHttpBuilder::new(),
        MagicHttpBuilder::new(),
    ];
    builders.sort_by_key(|b| b.preference());
    builders
});
