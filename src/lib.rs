// Deny unsafe code in the project by default, allow for exceptions though
#![deny(unsafe_code)]

use crate::acme::client::{AccountRegisterOptions, AcmeClient};
use crate::acme::http::HttpClient;
use crate::cert::{ParsedX509Certificate, load_certificates_from_memory};
use crate::challenge_solver::ChallengeSolver;
use crate::cli::{CommandLineSolverConfiguration, IssueCommand};
use crate::config::{
    AccountConfiguration, CertificateAuthorityConfiguration,
    CertificateAuthorityConfigurationWithAccounts, CertificateConfiguration, ConfigBackend,
    ConfigurationManager, DomainSolverMap, InstallerConfiguration, MainConfiguration,
    SolverConfiguration, config_directory,
};
use crate::crypto::asymmetric;
use crate::crypto::asymmetric::KeyType;
use crate::crypto::jws::{ExternalAccountBinding, JsonWebKey};
use crate::dns::name::DnsName;
use crate::dns::resolver::Resolver;
use crate::error::IssueResult;
use crate::issuer::{AcmeIssuer, AcmeIssuerWithAccount};
use crate::state::Database;
use crate::state::types::external::RenewalInformation;
use crate::time::humanize_duration;
use anyhow::{Context, Error, anyhow, bail};
use clap::ValueEnum;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::ops::Neg;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use strum::VariantArray;
use tracing::{error, info, warn};
use url::Url;

pub mod acme;
pub mod cert;
pub mod challenge_solver;
pub mod cli;
pub mod cmd_runner;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod interactive;
pub mod issuer;
pub mod magic;
pub mod non_interactive;
pub mod pebble;
pub mod renew;
pub mod state;
pub mod time;
pub mod util;

/// The name of the application
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
// As per RFC8555 Section 6.1, we should conform both to RFC 7525 and supply the name + version
// of our HTTP library.
pub const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " reqwest/",
    env!("REQWEST_VERSION"),
    " ( +",
    env!("CARGO_PKG_REPOSITORY"),
    " )"
);

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Identifier {
    Dns(DnsName),
}

impl Identifier {
    pub fn as_str(&self) -> &str {
        match self {
            Identifier::Dns(name) => name.as_ascii(),
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn as_ascii_domain_name(&self) -> Option<&str> {
        if let Identifier::Dns(name) = &self {
            return Some(name.as_ascii());
        }
        None
    }

    pub fn try_from_with_wildcard(
        acme_identifier: acme::object::Identifier,
    ) -> anyhow::Result<Self> {
        match acme_identifier {
            acme::object::Identifier::Dns { value } => {
                let dns = DnsName::try_from(format!("*.{value}"))
                    .context(format!("Failed to parse *.{value} as a DNS name"))?;
                Ok(Self::Dns(dns))
            }
            acme::object::Identifier::Unknown => {
                bail!("Unknown identifier type cannot be parsed")
            }
        }
    }
}

impl FromStr for Identifier {
    type Err = dns::name::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Identifier::Dns(s.try_into()?))
    }
}

impl From<Identifier> for acme::object::Identifier {
    fn from(value: Identifier) -> Self {
        match value {
            Identifier::Dns(name) => acme::object::Identifier::Dns {
                value: name.as_ascii().to_string(),
            },
        }
    }
}

impl TryFrom<acme::object::Identifier> for Identifier {
    type Error = Error;

    fn try_from(value: acme::object::Identifier) -> Result<Self, Self::Error> {
        match value {
            acme::object::Identifier::Dns { value } => {
                let dns = DnsName::try_from(value.as_str())
                    .context(format!("Failed to parse {value} as a DNS name"))?;
                Ok(Self::Dns(dns))
            }
            acme::object::Identifier::Unknown => {
                bail!("Unknown identifier type cannot be parsed")
            }
        }
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        match value {
            Identifier::Dns(name) => name.as_ascii().to_string(),
        }
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Identifier::Dns(name) => Display::fmt(name, f),
        }
    }
}

pub struct Authorizer {
    identifier: Identifier,
    solver: Box<dyn ChallengeSolver>,
}

impl Authorizer {
    pub fn new(identifier: Identifier, solver: impl ChallengeSolver + 'static) -> Self {
        Self::new_boxed(identifier, Box::new(solver))
    }

    pub fn new_boxed(identifier: Identifier, solver: Box<dyn ChallengeSolver>) -> Self {
        Self { identifier, solver }
    }
}

impl Debug for Authorizer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer")
            .field("identifier", &self.identifier)
            .field("solver", &self.solver.short_name())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, VariantArray)]
pub enum RevocationReason {
    /// No reason given, any reason.
    #[default]
    Unspecified,
    /// The certificate key was compromised. CAs will usually block the affected key in future certificates, and may even revoke other certificates with the same key.
    KeyCompromise,
    /// Refer to the CA documentation to determine if and when to use this reason code.
    AffiliationChanged,
    /// Refer to the CA documentation to determine if and when to use this reason code.
    Superseded,
    /// Refer to the CA documentation to determine if and when to use this reason code.
    CessationOfOperation,
    /// Refer to the CA documentation to determine if and when to use this reason code.
    PrivilegeWithdrawn,
}

impl Display for RevocationReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let clap_value = self
            .to_possible_value()
            .expect("Reason must not be skippable");
        write!(
            f,
            "{} - {}",
            clap_value.get_name(),
            clap_value.get_help().expect("Reason must have help text")
        )
    }
}

impl From<RevocationReason> for acme::object::RevocationReason {
    fn from(value: RevocationReason) -> Self {
        match value {
            RevocationReason::Unspecified => Self::Unspecified,
            RevocationReason::KeyCompromise => Self::KeyCompromise,
            RevocationReason::AffiliationChanged => Self::AffiliationChanged,
            RevocationReason::Superseded => Self::Superseded,
            RevocationReason::CessationOfOperation => Self::CessationOfOperation,
            RevocationReason::PrivilegeWithdrawn => Self::PrivilegeWithdrawn,
        }
    }
}

pub fn choose_solver_name(new_config: &SolverConfiguration, existing: &DomainSolverMap) -> String {
    let base_solver_name = new_config.name().to_string();
    let mut i = 0;
    let mut solver_name = base_solver_name.clone();
    while existing.solvers.contains_key(&solver_name) {
        i += 1;
        solver_name = format!("{base_solver_name}-{i}");
    }
    solver_name
}

pub fn build_domain_solver_maps(
    configs: Vec<(Vec<Identifier>, Option<String>, SolverConfiguration)>,
) -> anyhow::Result<DomainSolverMap> {
    let mut map = DomainSolverMap {
        domains: HashMap::new(),
        solvers: HashMap::new(),
    };
    for (solver_domains, solver_name, solver_config) in configs {
        let solver_name = solver_name.unwrap_or_else(|| choose_solver_name(&solver_config, &map));
        if map
            .solvers
            .insert(solver_name.clone(), solver_config.clone())
            .is_some()
        {
            bail!("Duplicate solver name: {solver_name}");
        }

        for identifier in solver_domains {
            if map
                .domains
                .insert(identifier.clone(), solver_name.clone())
                .is_some()
            {
                bail!("Duplicate domain name: {identifier}");
            }
        }
    }
    Ok(map)
}

pub async fn domain_solver_maps_from_command_line(
    cmd_line_config: Vec<CommandLineSolverConfiguration>,
) -> anyhow::Result<DomainSolverMap> {
    let mut solver_configs = Vec::with_capacity(cmd_line_config.len());
    for solver_config in cmd_line_config {
        let new_config = solver_config
            .solver
            .build_from_command_line(&solver_config)
            .await?;
        let domains = solver_config.base.domains;
        let name = solver_config.base.name;
        solver_configs.push((domains, name, new_config));
    }
    build_domain_solver_maps(solver_configs)
}

pub fn authorizers_from_config(
    config: CertificateConfiguration,
) -> anyhow::Result<Vec<Authorizer>> {
    let size = config.domains_and_solvers.domains.len();
    let mut authorizers = Vec::with_capacity(size);
    for (domain, solver_name) in config.domains_and_solvers.domains.into_iter().sorted() {
        let acme_domain = domain.clone();
        if authorizers
            .iter()
            .any(|authorizer: &Authorizer| authorizer.identifier == acme_domain)
        {
            bail!("Duplicate domain {domain} in config");
        }

        let solver_config = config
            .domains_and_solvers
            .solvers
            .get(&solver_name)
            .cloned()
            .ok_or(anyhow!("Solver {solver_name} not found"))?;
        let solver = solver_config.to_solver()?;
        authorizers.push(Authorizer::new_boxed(domain, solver));
    }
    Ok(authorizers)
}

async fn modify_certificate_config(
    mut cert: CertificateConfiguration,
    modify: IssueCommand,
) -> anyhow::Result<CertificateConfiguration> {
    if let Some(ca) = modify.ca {
        cert.ca_identifier = ca;
    }
    if let Some(acc) = modify.account {
        cert.account_identifier = acc;
    }
    if let Some(name) = modify.cert_name {
        cert.display_name = name;
    }
    if let Some(install) = modify.install_script {
        cert.installer = Some(InstallerConfiguration::Script { script: install });
    }
    if let Some(key_type) = modify.advanced.key_type {
        cert.key_type = key_type.into();
    }
    if let Some(lifetime) = modify.advanced.lifetime {
        cert.advanced.lifetime_seconds = Some(lifetime.as_secs());
    }
    if let Some(profile) = modify.advanced.profile {
        // TODO: Profile validation
        cert.advanced.profile = Some(profile);
    }
    cert.advanced.reuse_key = modify.advanced.reuse_key;
    let domains_and_solvers =
        domain_solver_maps_from_command_line(modify.solver_configuration).await?;
    if !domains_and_solvers.domains.is_empty() {
        cert.domains_and_solvers = domains_and_solvers;
    }
    Ok(cert)
}

/// Note: This is not collision-free. Use `Certonaut::choose_cert_id_from_display_name` instead.
fn cert_id_from_display_name(display_name: &str) -> String {
    // TODO: The names choosen by this function are non-ideal for IDN names
    let mut id_str = String::new();
    for char in display_name.chars() {
        if char.is_ascii_alphanumeric() || char == '_' || char == '-' || char == '.' {
            id_str.push(char);
        } else {
            id_str.push('_');
        }
    }
    id_str
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeProfile {
    name: String,
    description: String,
}

impl AcmeProfile {
    pub fn new(name: String, description: String) -> Self {
        Self { name, description }
    }
}

impl Display for AcmeProfile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = &self.name;
        let description = &self.description;
        write!(f, "{name}: {description}")
    }
}

pub struct NewAccountOptions {
    pub name: String,
    pub identifier: String,
    pub contacts: Vec<Url>,
    pub key_type: KeyType,
    pub terms_of_service_agreed: Option<bool>,
    pub external_account_binding: Option<ExternalAccountBinding>,
}

#[derive(Debug)]
pub struct AcmeAccount {
    pub config: AccountConfiguration,
    pub jwk: JsonWebKey,
}

impl AcmeAccount {
    pub fn load_existing(config: AccountConfiguration) -> Result<Self, Error> {
        let key_path = &config.key_file;
        let key_file = File::open(key_path)
            .context(format!("Cannot read account key {}", key_path.display()))?;
        let keypair = asymmetric::KeyPair::load_from_disk(key_file)?;
        let jwk = JsonWebKey::new_existing(keypair, config.url.clone());
        // TODO: Validate accounts at CA, retrieve metadata?
        Ok(Self { config, jwk })
    }

    pub fn new_account(config: AccountConfiguration, jwk: JsonWebKey) -> Self {
        Self { config, jwk }
    }

    pub fn get_config(&self) -> &AccountConfiguration {
        &self.config
    }
}

async fn new_acme_client(
    ca_config: &CertificateAuthorityConfiguration,
) -> Result<AcmeClient, Error> {
    let name = &ca_config.name;
    let http_client = if ca_config.trusted_roots.is_empty() {
        HttpClient::try_new()?
    } else {
        let root_certs = cert::load_reqwest_certificates(ca_config.trusted_roots.iter()).await?;
        HttpClient::try_new_with_custom_roots(root_certs)?
    };
    let client = acme::client::AcmeClientBuilder::new(ca_config.acme_directory.clone())
        .with_http_client(http_client)
        .try_build()
        .await
        .context(format!("Establishing connection to CA {name}"))?;
    Ok(client)
}

#[derive(Debug)]
pub struct Certonaut<CB> {
    issuers: HashMap<String, AcmeIssuer>,
    certificates: HashMap<String, CertificateConfiguration>,
    database: Database,
    config: ConfigurationManager<CB>,
    resolver: Arc<Resolver>,
}

impl<CB: ConfigBackend> Certonaut<CB> {
    pub fn try_new(
        manager: ConfigurationManager<CB>,
        database: Database,
        resolver: Resolver,
    ) -> anyhow::Result<Self> {
        let resolver = Arc::new(resolver);
        let config = manager.load()?;
        let mut issuers = HashMap::new();
        for ca in config.main.ca_list {
            let id = ca.inner.identifier.clone();
            let issuer = AcmeIssuer::try_new(ca, resolver.clone())?;
            if let Some(old) = issuers.insert(id, issuer) {
                let id = old.config.identifier;
                bail!("Duplicate CA id {id} in configuration");
            }
        }
        Ok(Self {
            issuers,
            certificates: config.certificates,
            database,
            config: manager,
            resolver,
        })
    }

    pub fn get_ca(&self, id: &str) -> Option<&AcmeIssuer> {
        self.issuers.get(id)
    }

    pub fn get_ca_mut(&mut self, id: &str) -> Option<&mut AcmeIssuer> {
        self.issuers.get_mut(id)
    }

    pub fn get_default_ca(&self) -> Option<&AcmeIssuer> {
        self.issuers.values().find(|issuer| issuer.config.default)
    }

    pub fn get_certificate(&self, id: &str) -> Option<&CertificateConfiguration> {
        self.certificates.get(id)
    }

    pub fn replace_certificate(
        &mut self,
        id: &str,
        new_certificate: CertificateConfiguration,
    ) -> Result<(), Error> {
        let maybe_err = self
            .config
            .save_certificate_config(id, &new_certificate)
            .context("Saving new configuration");
        self.certificates.insert(id.to_string(), new_certificate);
        maybe_err
    }

    pub fn get_issuer_with_account(
        &self,
        issuer: &str,
        account: &str,
    ) -> anyhow::Result<AcmeIssuerWithAccount> {
        self.get_ca(issuer)
            .ok_or(anyhow!("CA {issuer} not found"))?
            .with_account(account)
            .ok_or(anyhow!("Account {account} not found"))
    }

    pub fn current_main_config(&self) -> MainConfiguration {
        MainConfiguration {
            ca_list: self
                .issuers
                .values()
                .sorted_by_key(|issuer| issuer.config.name.clone())
                .map(AcmeIssuer::current_config)
                .collect(),
        }
    }

    pub async fn create_account(
        client: &AcmeClient,
        options: NewAccountOptions,
    ) -> Result<AcmeAccount, Error> {
        let keypair =
            asymmetric::new_key(options.key_type).context("Generating new account key")?;
        let mut account_name = options.name;
        if account_name.is_empty() {
            account_name.clone_from(&options.identifier);
        }
        let account_id = options.identifier;
        let config_path = config_directory();
        let key_path = config_path
            .join("account_keys")
            .join(format!("{account_id}.key"));
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).context("Creating account key directory")?;
        }
        let account_file = File::create_new(&key_path).context("Saving account key to file")?;
        keypair
            .save_to_disk(account_file)
            .context("Saving account key to file")?;
        let key_path = key_path
            .canonicalize()
            .context("Saving account key to file")?;

        let options = AccountRegisterOptions {
            key: keypair,
            contact: options.contacts,
            terms_of_service_agreed: options.terms_of_service_agreed,
            external_account_binding: options.external_account_binding,
        };
        let (jwk, url, _account) = match client
            .register_account(options)
            .await
            .context("Registering account at CA failed")
        {
            Ok((jwk, url, account)) => (jwk, url, account),
            Err(err) => {
                // Remove the account key we just created to avoid a conflict if the user retries
                std::fs::remove_file(&key_path).ok(); // We're already reporting a fatal error, swallow the cleanup problem
                bail!(err)
            }
        };

        let config = AccountConfiguration {
            name: account_name,
            identifier: account_id,
            key_file: key_path,
            url,
        };
        Ok(AcmeAccount::new_account(config, jwk))
    }

    pub fn add_new_ca(&mut self, new_ca: CertificateAuthorityConfiguration) -> Result<(), Error> {
        let id = new_ca.identifier.clone();
        let new_ca = CertificateAuthorityConfigurationWithAccounts {
            inner: new_ca,
            accounts: vec![],
        };
        let issuer = AcmeIssuer::try_new(new_ca, self.resolver.clone())?;
        if issuer.config.default {
            self.issuers
                .values_mut()
                .for_each(|ca| ca.config.default = false);
        }
        self.issuers.insert(id, issuer);
        self.config
            .save_main(&self.current_main_config())
            .context("Saving new configuration")?;
        Ok(())
    }

    pub fn add_new_account(&mut self, ca_id: &str, new_account: AcmeAccount) -> Result<(), Error> {
        let ca = self
            .get_ca_mut(ca_id)
            .ok_or(anyhow::anyhow!("CA {ca_id} not found"))?;
        ca.add_account(new_account);
        self.config
            .save_main(&self.current_main_config())
            .context("Saving new configuration")?;
        Ok(())
    }

    pub fn choose_ca_id_from_name(&self, friendly_name: &str) -> String {
        // TODO: Append -test if a test CA and name conflicts?
        let mut ca_id = friendly_name.trim().to_lowercase().replace(' ', "-");
        ca_id.retain(|c| c.is_ascii_alphanumeric() || c == '-');
        let mut ca_num = self.issuers.len();
        if ca_id.is_empty() {
            ca_id = format!("ca-{ca_num}");
        }
        let ca_id_base = ca_id.clone();
        while self.get_ca(&ca_id).is_some() {
            ca_num += 1;
            ca_id = format!("{ca_id_base}-{ca_num}");
        }
        ca_id
    }

    pub fn choose_cert_name_from_domains<'a, I: Iterator<Item = &'a Identifier>>(
        &'a self,
        identifiers: I,
    ) -> String {
        let identifiers = identifiers.sorted().collect::<Vec<_>>();
        for identifier in &identifiers {
            let name = identifier.to_string();
            let test_id = cert_id_from_display_name(&name);
            if !self.certificates.contains_key(&test_id) {
                return name;
            }
        }
        // No free name in identifiers, so try something else
        let base_name = if let Some(identifier) = identifiers.first() {
            identifier.to_string()
        } else {
            "default".to_string()
        };
        let mut i = 1;
        let mut name = base_name.clone();
        let mut test_id = cert_id_from_display_name(&name);
        while self.certificates.contains_key(&test_id) {
            name = format!("{base_name}-{i}");
            test_id = cert_id_from_display_name(&name);
            i += 1;
        }
        name
    }

    pub fn choose_cert_id_from_display_name(&self, display_name: &str) -> String {
        let cert_id_base = cert_id_from_display_name(display_name);
        let mut cert_id = cert_id_base.clone();
        let mut i = 0;
        while self.certificates.contains_key(&cert_id) {
            i += 1;
            cert_id = format!("{cert_id_base}-{i}");
        }
        cert_id
    }

    pub fn remove_account(&mut self, issuer_id: &str, account_id: &str) -> Result<(), Error> {
        let deleted_account = self
            .get_ca_mut(issuer_id)
            .and_then(|issuer| issuer.remove_account(account_id));
        if let Some(deleted_account) = deleted_account {
            self.config
                .save_main(&self.current_main_config())
                .context("Saving new configuration")?;
            if let Err(e) = std::fs::remove_file(deleted_account.config.key_file) {
                warn!("Failed to delete account key: {}", e);
            }
            Ok(())
        } else {
            bail!("Something went wrong while removing account from configuration");
        }
    }

    pub fn remove_ca(&mut self, issuer_id: &str) -> Result<(), Error> {
        // TODO: Check if there are existing accounts or certs referencing the CA
        self.issuers
            .remove(issuer_id)
            .ok_or(anyhow::anyhow!("CA {issuer_id} not found"))?;
        self.config
            .save_main(&self.current_main_config())
            .context("Saving new configuration")?;
        Ok(())
    }

    pub async fn issue_new(&self, cert_config: CertificateConfiguration) -> Result<(), Error> {
        let cert_id = self.choose_cert_id_from_display_name(&cert_config.display_name);
        let authorizers = authorizers_from_config(cert_config.clone())?;
        let issuer = self
            .get_issuer_with_account(&cert_config.ca_identifier, &cert_config.account_identifier)?;
        let ca_name = &issuer.issuer.config.name;
        let key_type = cert_config.key_type;
        let cert_key = asymmetric::new_key(key_type).context(format!(
            "Could not generate certificate key with type {key_type}"
        ))?;
        let lifetime = cert_config
            .advanced
            .lifetime_seconds
            .map(|lifetime| Some(Duration::from_secs(lifetime)))
            .unwrap_or_default();
        let cert = issuer
            .issue(
                &cert_key,
                lifetime,
                authorizers,
                None,
                cert_config.advanced.profile.clone(),
            )
            .await
            .context(format!("Issuing certificate with CA {ca_name}"))?;
        println!(
            "Successfully issued certificate {} with CA {ca_name}",
            cert_config.display_name
        );
        self.config
            .save_certificate_and_config(&cert_id, &cert_config, &cert_key, &cert)?;
        match load_certificates_from_memory(&cert.pem, Some(1)) {
            Ok(parsed_certs) => {
                if let Some(parsed_cert) = parsed_certs.first() {
                    self.try_fetch_and_store_ari(&issuer, cert_id.to_string(), parsed_cert)
                        .await;
                } else {
                    warn!("No certificate found in new certificate from CA");
                }
            }
            Err(e) => {
                warn!("Failed to parse new certificate from CA: {e:#}");
            }
        }
        self.install_certificate(&cert_id, &cert_config)
            .await
            .context(format!(
                "Installing certificate {}",
                cert_config.display_name
            ))?;
        Ok(())
    }

    pub async fn renew_certificate(
        &self,
        issuer: &AcmeIssuerWithAccount<'_>,
        cert_id: &str,
        cert_config: &CertificateConfiguration,
        old_cert: &ParsedX509Certificate,
    ) -> IssueResult<()> {
        let inner_renewal_fn = async || {
            let cert_name = &cert_config.display_name;
            info!(
                "Renewing certificate {cert_name} at CA {}",
                issuer.issuer.config.name
            );
            let cert_key = if cert_config.advanced.reuse_key {
                self.config.load_certificate_private_key(cert_id)
            } else {
                asymmetric::new_key(cert_config.key_type)
            }?;
            let authorizers = authorizers_from_config(cert_config.clone())?;
            let lifetime = cert_config
                .advanced
                .lifetime_seconds
                .map(|lifetime| Some(Duration::from_secs(lifetime)))
                .unwrap_or_default();
            let renewal_identifier = old_cert.acme_renewal_identifier.clone();
            let issue_result = issuer
                .issue(
                    &cert_key,
                    lifetime,
                    authorizers,
                    renewal_identifier,
                    cert_config.advanced.profile.clone(),
                )
                .await;
            if let Ok(new_cert) = &issue_result {
                self.config.save_certificate_and_config(
                    cert_id,
                    cert_config,
                    &cert_key,
                    new_cert,
                )?;
                match load_certificates_from_memory(&new_cert.pem, Some(1)) {
                    Ok(parsed_certs) => {
                        if let Some(parsed_cert) = parsed_certs.first() {
                            self.try_fetch_and_store_ari(issuer, cert_id.to_string(), parsed_cert)
                                .await;
                        } else {
                            warn!("No certificate found in renewed certificate from CA");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse renewed certificate from CA: {e:#}");
                    }
                }
            }
            issue_result
        };
        let renewal_result = inner_renewal_fn().await;

        if let Err(db_error) = self
            .database
            .add_new_renewal(cert_id, &renewal_result)
            .await
        {
            error!("Failed to store renewal in database: {db_error}");
        }
        renewal_result.map(|_| ())
    }

    pub async fn install_certificate(
        &self,
        cert_id: &str,
        cert_config: &CertificateConfiguration,
    ) -> Result<(), Error> {
        if let Some(installer_config) = &cert_config.installer {
            match installer_config {
                InstallerConfiguration::Script { script } => {
                    let config_dir = self.config.certificate_directory(cert_id);
                    let env = HashMap::from([
                        (
                            <str as AsRef<OsStr>>::as_ref("RENEWED_LINEAGE").to_os_string(),
                            config_dir.into_os_string(),
                        ),
                        (
                            <str as AsRef<OsStr>>::as_ref("RENEWED_DOMAINS").to_os_string(),
                            <String as AsRef<OsStr>>::as_ref(
                                &cert_config
                                    .domains_and_solvers
                                    .domains
                                    .keys()
                                    .sorted()
                                    .join(" "),
                            )
                            .to_os_string(),
                        ),
                    ]);
                    let status = cmd_runner::run_shell_command(script.as_ref(), env)
                        .await
                        .context("Launching installer command {script:?} failed")?;
                    if !status.success() {
                        let Some(status_code) = status.code() else {
                            if let Some(signal) = {
                                #[cfg(unix)]
                                {
                                    std::os::unix::process::ExitStatusExt::signal(&status)
                                }
                                #[cfg(not(unix))]
                                {
                                    None::<i32>
                                }
                            } {
                                bail!(
                                    "Installer command {script:?} was interrupted by signal {signal}"
                                )
                            }
                            bail!("Installer command {script:?} was terminated for unknown reason")
                        };
                        bail!(
                            "Installer command {script:?} exited with non-zero status code {status_code}"
                        );
                    }
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    pub async fn revoke_certificate(
        &self,
        cert_id: &str,
        reason: Option<RevocationReason>,
    ) -> anyhow::Result<()> {
        let certificate_config = self
            .get_certificate(cert_id)
            .context(format!("Cert {cert_id} not found"))?;
        let parsed_cert = self
            .config
            .load_certificate_files(cert_id, Some(1))?
            .pop()
            .context(format!(
                "No certificate found in certificate file for {cert_id}"
            ))?;
        let maybe_err = match self.config.load_certificate_private_key(cert_id) {
            Ok(cert_key) => {
                match self
                    .get_ca(&certificate_config.ca_identifier)
                    .context(format!("CA {} not found", certificate_config.ca_identifier))
                {
                    Ok(issuer) => {
                        issuer
                            .revoke_with_cert_key(&parsed_cert, cert_key, reason)
                            .await
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e.context(format!("Cannot load private key for {cert_id}"))),
        };
        if let Err(e) = maybe_err {
            warn!("Revoking certificate with certificate key failed: {e:#}");
            warn!("Attempting revocation using account key instead");
            let issuer = self.get_issuer_with_account(
                &certificate_config.ca_identifier,
                &certificate_config.account_identifier,
            )?;
            issuer.revoke_with_account_key(&parsed_cert, reason).await?;
        }
        // Also attempt an ARI update after revocation, if possible
        if let Some(issuer) = self.get_ca(&certificate_config.ca_identifier) {
            self.try_fetch_and_store_ari(issuer, cert_id.to_string(), &parsed_cert)
                .await;
        }
        Ok(())
    }

    pub async fn try_fetch_and_store_ari(
        &self,
        issuer: &AcmeIssuer,
        cert_id: String,
        cert: &ParsedX509Certificate,
    ) -> Option<RenewalInformation> {
        let new_renewal_info = issuer
            .get_renewal_info(cert_id, cert)
            .await
            .unwrap_or_else(|e| {
                warn!("{e:#}");
                None
            });
        if let Some(new_renewal_info) = new_renewal_info.clone() {
            if let Err(e) = self
                .database
                .set_renewal_information(new_renewal_info)
                .await
            {
                error!("Failed to store latest ARI result: {e:#}");
            }
        }
        new_renewal_info
    }

    pub fn maintenance_task(&self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        self.database.background_cleanup()
    }

    pub async fn print_accounts(&self) {
        let mut has_accounts = false;
        for issuer in self
            .issuers
            .values()
            .sorted_by_key(|issuer| issuer.config.name.as_str())
        {
            if issuer.num_accounts() == 0 {
                continue;
            }
            has_accounts = true;
            println!(
                "=== CA: Name: {}, ID: {} ===",
                issuer.config.name, issuer.config.identifier
            );
            for account_id in issuer
                .get_accounts()
                .sorted_by_key(|account| account.config.name.clone())
                .map(|account| &account.config.identifier)
            {
                if let Some(account) = issuer.with_account(account_id) {
                    Self::print_account(&account).await;
                }
            }
            println!();
        }

        if !has_accounts {
            let config_dir = config_directory();
            println!(
                "There are currently no ACME accounts configured within {CRATE_NAME}'s config"
            );
            println!(
                "Hint: Either create a new account, or verify that the configuration file @ {} is correct",
                config_dir.display()
            );
        }
    }

    pub async fn print_account<'a>(account: &'a AcmeIssuerWithAccount<'a>) {
        let issuer = account.issuer;
        let account = account.account;
        println!("=== Account {} ===", account.config.name);
        println!("ID: {}", account.config.identifier);
        println!("Account Key: {}", account.config.key_file.display());
        println!("Account URL: {}", account.config.url);

        match issuer.client().await {
            Ok(client) => match client
                .fetch_account(&account.jwk, &account.get_config().url)
                .await
            {
                Ok(account) => {
                    println!("Status: {}", account.status);
                    println!("Contact: {}", account.contact.into_iter().join(", "));
                    if let Some(eab_header) = account
                        .external_account_binding
                        .and_then(|eab| eab.header_json().ok())
                    {
                        println!("External Account Binding: {eab_header}");
                    }
                }
                Err(e) => {
                    warn!("Failed to retrieve account from CA: {e:#}");
                }
            },
            Err(e) => {
                warn!("Failed to retrieve account from CA: {e:#}");
            }
        }
    }

    pub async fn print_issuers(&self) {
        let has_issuers = !self.issuers.is_empty();
        for issuer in self
            .issuers
            .values()
            .sorted_by_key(|issuer| issuer.config.name.as_str())
        {
            Self::print_issuer(issuer).await;
            println!();
        }

        if !has_issuers {
            let config_dir = config_directory();
            println!(
                "There are currently no certificate authorities configured within {CRATE_NAME}'s config"
            );
            println!(
                "Hint: Either add a new CA, or verify that the configuration file @ {} is correct",
                config_dir.display()
            );
        }
    }

    pub async fn print_issuer(issuer: &AcmeIssuer) {
        println!("=== {} ===", issuer.config.name);
        println!("ID: {}", issuer.config.identifier);
        println!("ACME directory URL: {}", issuer.config.acme_directory);
        let flags = [
            ("default", issuer.config.default),
            ("testing", issuer.config.testing),
            ("public", issuer.config.public),
        ];
        let flags = flags
            .iter()
            .filter(|(_, value)| *value)
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
        println!("Flags: {flags}");

        match issuer.client().await {
            Ok(client) => {
                let directory = client.get_directory();
                if let Some(meta) = &directory.meta {
                    if let Some(website) = &meta.website {
                        println!("Website: {website}");
                    }
                    if let Some(tos) = &meta.terms_of_service {
                        println!("Terms of Service: {tos}");
                    }
                    println!(
                        "External account required: {}",
                        if meta.external_account_required {
                            "yes"
                        } else {
                            "no"
                        }
                    );
                    let caa = meta.caa_identities.join(", ");
                    if !caa.is_empty() {
                        println!("Valid CAA names: {caa}");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to retrieve ACME directory: {e:#}");
            }
        }
    }

    pub fn print_certificates(&self) {
        let has_certificates = !self.certificates.is_empty();
        for (cert_id, cert) in self
            .certificates
            .iter()
            .sorted_by_key(|(_, cert)| cert.display_name.as_str())
        {
            self.print_certificate(cert_id, cert);
            println!();
        }

        if !has_certificates {
            let config_dir = config_directory();
            println!("There are currently no certificates known within {CRATE_NAME}'s config");
            println!(
                "Hint: Either issue a new certificate, or verify that the configuration file @ {} is correct",
                config_dir.display()
            );
        }
    }

    pub fn print_certificate(&self, cert_id: &str, cert: &CertificateConfiguration) {
        println!("=== {} ===", cert.display_name);
        println!("ID: {cert_id}");
        println!(
            "Domains: {}",
            cert.domains_and_solvers.domains.keys().sorted().join(", ")
        );
        let ca_name = self
            .issuers
            .get(&cert.ca_identifier)
            .map_or("CA not found".to_string(), |ca| ca.config.name.clone());
        println!("CA: {ca_name} (ID: {})", cert.ca_identifier);
        println!("Account ID: {}", cert.account_identifier);
        println!("Key Type: {}", cert.key_type);
        println!(
            "Renew disabled: {}",
            if cert.auto_renew { "no" } else { "yes" }
        );
        println!(
            "Key reuse: {}",
            if cert.advanced.reuse_key { "yes" } else { "no" }
        );
        let mut cert_dir = self.config.certificate_directory(cert_id);
        // To ensure the returned path is a directory
        cert_dir.push("");
        println!("Certificate directory: {}", cert_dir.display());

        match self.config.load_certificate_files(cert_id, Some(1)) {
            Ok(x509_certs) => {
                if let Some(cert) = x509_certs.first() {
                    let serial = cert.serial.to_bytes_be();
                    println!(
                        "Certificate Serial: {}",
                        util::format_hex_with_colon(serial)
                    );
                    let spki = &cert.subject_public_key_sha256;
                    println!(
                        "Public Key Hash (SHA256): {}",
                        util::format_hex_with_colon(spki)
                    );

                    let not_after = cert.validity.not_after.to_string();
                    let time_until_expired = cert.validity.time_to_expiration();
                    if time_until_expired > ::time::Duration::ZERO {
                        let time_until_expired = humanize_duration(time_until_expired);
                        println!(
                            "Certificate is valid until: {not_after} (Expires in {time_until_expired})",
                        );
                    } else {
                        let expired_since = time_until_expired.neg();
                        let expired_since = humanize_duration(expired_since);
                        println!(
                            "Certificate is valid until: {not_after} (EXPIRED {expired_since} ago)"
                        );
                    }
                } else {
                    warn!(
                        "Failed to load certificate {}: No certificate found in file",
                        cert.display_name
                    );
                }
            }
            Err(error) => {
                warn!(
                    "Failed to load certificate {}: {:#}",
                    cert.display_name, error
                );
            }
        }
    }
}
