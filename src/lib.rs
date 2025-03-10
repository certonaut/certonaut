#![forbid(unsafe_code)]

use crate::acme::client::{AccountRegisterOptions, AcmeClient, DownloadedCertificate};
use crate::acme::error::Problem;
use crate::acme::http::HttpClient;
use crate::acme::object::{
    AccountStatus, AuthorizationStatus, ChallengeStatus, Identifier, InnerChallenge,
    NewOrderRequest, Order, OrderStatus,
};
use crate::cert::ParsedX509Certificate;
use crate::challenge_solver::{ChallengeSolver, DomainsWithSolverConfiguration, KeyAuthorization};
use crate::config::{
    AccountConfiguration, CertificateAuthorityConfiguration,
    CertificateAuthorityConfigurationWithAccounts, CertificateConfiguration, Configuration,
    MainConfiguration, SolverConfiguration, config_directory,
};
use crate::crypto::asymmetric;
use crate::crypto::asymmetric::KeyType;
use crate::crypto::jws::JsonWebKey;
use crate::error::{IssueContext, IssueResult};
use crate::pebble::pebble_root;
use crate::state::Database;
use crate::util::humanize_duration_core;
use anyhow::{Context, Error, anyhow, bail};
use itertools::Itertools;
use rcgen::CertificateSigningRequest;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use time::error::ConversionRange;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};
use url::Url;

pub mod acme;
pub mod cert;
pub mod challenge_solver;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod interactive;
pub mod magic;
pub mod pebble;
pub mod renew;
pub mod state;
pub mod util;

/// The name of the application
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// The maximum number of certificates we will parse in a PEM-array of certificates by default
const DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH: usize = 100;

pub struct DomainSolverMap {
    pub domains: HashMap<Identifier, String>,
    pub solvers: HashMap<String, SolverConfiguration>,
}

impl
    From<(
        HashMap<Identifier, String>,
        HashMap<String, SolverConfiguration>,
    )> for DomainSolverMap
{
    fn from(
        (domains, solvers): (
            HashMap<Identifier, String>,
            HashMap<String, SolverConfiguration>,
        ),
    ) -> Self {
        Self { domains, solvers }
    }
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    cyborgtime::parse_duration(s).map_err(|e| format!("Invalid duration: {e}"))
}

#[derive(Clone)]
pub struct ParsedDuration {
    inner: Duration,
}

impl From<Duration> for ParsedDuration {
    fn from(inner: Duration) -> Self {
        ParsedDuration { inner }
    }
}

impl Deref for ParsedDuration {
    type Target = Duration;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FromStr for ParsedDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_duration(s).map(ParsedDuration::from)
    }
}

impl Display for ParsedDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match humanize_duration_core(**self) {
            Ok(duration) => write!(f, "{duration}"),
            Err(_) => write!(f, "Time too long to display"),
        }
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn current_time_truncated() -> time::OffsetDateTime {
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap(/* unreachable */)
}

// TODO: must-staple option
fn create_and_sign_csr(
    cert_key: &rcgen::KeyPair,
    identifiers: Vec<Identifier>,
) -> Result<CertificateSigningRequest, Error> {
    let mut cert_params = rcgen::CertificateParams::new(
        identifiers
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>(),
    )
    .context("CSR generation failed")?;
    // Ensure the DN is empty
    cert_params.distinguished_name = rcgen::DistinguishedName::default();
    let csr = cert_params
        .serialize_request(cert_key)
        .context("Signing CSR failed")?;
    Ok(csr)
}

pub fn load_certificates_from_file<P: AsRef<Path>>(
    cert_file: P,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let cert_file = cert_file.as_ref();
    let cert_file_display = cert_file.display();
    let cert_file = File::open(cert_file).context(format!("Opening {cert_file_display} failed"))?;
    let reader = BufReader::new(cert_file);
    load_certificates_from_reader(reader, limit)
        .context(format!("Parsing certificate {cert_file_display} failed"))
}

pub fn load_certificates_from_memory<B: AsRef<[u8]>>(
    pem_bytes: B,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let reader = Cursor::new(pem_bytes);
    load_certificates_from_reader(reader, limit)
}

fn load_certificates_from_reader<R: BufRead + Seek>(
    reader: R,
    limit: Option<usize>,
) -> anyhow::Result<Vec<ParsedX509Certificate>> {
    let mut certificates = Vec::new();
    for pem in x509_parser::pem::Pem::iter_from_reader(reader)
        .take(limit.unwrap_or(DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH))
    {
        let pem = pem.context("Reading PEM block failed")?;
        let parser_x509 = pem
            .parse_x509()
            .context("Reading X509 structure: Decoding DER failed")?;
        certificates.push(parser_x509.into());
    }
    Ok(certificates)
}

pub struct Authorizer {
    identifier: Identifier,
    solver_name: Option<String>,
    solver: Box<dyn ChallengeSolver>,
}

impl Authorizer {
    pub fn new(
        identifier: Identifier,
        name: Option<String>,
        solver: impl ChallengeSolver + 'static,
    ) -> Self {
        Self::new_boxed(identifier, name, Box::new(solver))
    }

    pub fn new_boxed(
        identifier: Identifier,
        name: Option<String>,
        solver: Box<dyn ChallengeSolver>,
    ) -> Self {
        Self {
            identifier,
            solver_name: name,
            solver,
        }
    }
}

impl Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer")
            .field("identifier", &self.identifier)
            .field("solver_name", &self.solver_name)
            .field("solver", &self.solver.short_name())
            .finish()
    }
}

pub fn build_domain_solver_maps(
    configs: Vec<DomainsWithSolverConfiguration>,
) -> anyhow::Result<DomainSolverMap> {
    let mut domains = HashMap::new();
    let mut solvers = HashMap::new();
    for solver_config in configs {
        let solver_name = solver_config.solver_name.clone().unwrap_or_else(|| {
            let base_solver_name = solver_config.config.name().to_string();
            let mut i = 0;
            let mut solver_name = base_solver_name.clone();
            while solvers.contains_key(&solver_name) {
                i += 1;
                solver_name = format!("{base_solver_name}-{i}");
            }
            solver_name
        });
        if solvers
            .insert(solver_name.clone(), solver_config.config.clone())
            .is_some()
        {
            bail!("Duplicate solver name: {solver_name}");
        };

        for identifier in solver_config.domains {
            if domains
                .insert(identifier.clone(), solver_name.clone())
                .is_some()
            {
                bail!("Duplicate domain name: {identifier}");
            }
        }
    }
    Ok((domains, solvers).into())
}

pub fn authorizers_from_config(
    config: CertificateConfiguration,
) -> anyhow::Result<Vec<Authorizer>> {
    let size = config.domains.len();
    let mut authorizers = Vec::with_capacity(size);
    for (domain, solver_name) in config.domains.into_iter().sorted() {
        let id = Identifier::from(domain);
        if authorizers
            .iter()
            .any(|authorizer: &Authorizer| authorizer.identifier == id)
        {
            bail!("Duplicate domain {id} in config");
        }

        let solver_config = config
            .solvers
            .get(&solver_name)
            .cloned()
            .ok_or(anyhow!("Solver {solver_name} not found"))?;
        let solver = solver_config.to_solver()?;
        authorizers.push(Authorizer::new_boxed(id, Some(solver_name), solver));
    }
    Ok(authorizers)
}

/// Note: This is not collision-free. Use `Certonaut::choose_cert_id_from_display_name` instead.
fn cert_id_from_display_name(display_name: &str) -> String {
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

pub struct NewAccountOptions {
    pub name: String,
    pub identifier: String,
    pub contacts: Vec<Url>,
    pub key_type: KeyType,
    pub terms_of_service_agreed: Option<bool>,
}

#[derive(Debug)]
pub struct AcmeAccount {
    config: AccountConfiguration,
    jwk: JsonWebKey,
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
    // TODO: Temporary measure for easy pebble tests
    let http_client = HttpClient::try_new_with_custom_root(pebble_root()?)?;
    let client = acme::client::AcmeClientBuilder::new(ca_config.acme_directory.clone())
        .with_http_client(http_client)
        .try_build()
        .await
        .context(format!("Establishing connection to CA {name}"))?;
    Ok(client)
}

#[derive(Debug)]
pub struct Certonaut {
    issuers: HashMap<String, AcmeIssuer>,
    certificates: HashMap<String, CertificateConfiguration>,
    database: Database,
}

impl Certonaut {
    pub async fn try_new(config: Configuration) -> anyhow::Result<Self> {
        let mut issuers = HashMap::new();
        for ca in config.main.ca_list {
            let id = ca.inner.identifier.clone();
            let issuer = AcmeIssuer::try_new(ca)?;
            if let Some(old) = issuers.insert(id, issuer) {
                let id = old.config.identifier;
                bail!("Duplicate CA id {id} in configuration");
            };
        }
        let database = Database::open(config_directory(), "database.sqlite").await?;
        Ok(Self {
            issuers,
            certificates: config.certificates,
            database,
        })
    }

    pub fn get_ca(&self, id: &str) -> Option<&AcmeIssuer> {
        self.issuers.get(id)
    }

    pub fn get_ca_mut(&mut self, id: &str) -> Option<&mut AcmeIssuer> {
        self.issuers.get_mut(id)
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

    pub fn current_config(&self) -> Configuration {
        Configuration {
            main: MainConfiguration {
                ca_list: self
                    .issuers
                    .values()
                    .sorted_by_key(|issuer| issuer.config.name.clone())
                    .map(AcmeIssuer::current_config)
                    .collect(),
            },
            certificates: self.certificates.clone(),
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
        let issuer = AcmeIssuer::try_new(new_ca)?;
        self.issuers.insert(id, issuer);
        config::save(&self.current_config()).context("Saving new configuration")?;
        Ok(())
    }

    pub fn add_new_account(&mut self, ca_id: &str, new_account: AcmeAccount) -> Result<(), Error> {
        let ca = self
            .get_ca_mut(ca_id)
            .ok_or(anyhow::anyhow!("CA {ca_id} not found"))?;
        ca.add_account(new_account);
        config::save(&self.current_config()).context("Saving new configuration")?;
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
            config::save(&self.current_config()).context("Saving new configuration")?;
            if let Err(e) = std::fs::remove_file(deleted_account.config.key_file) {
                warn!("Failed to delete account key: {}", e);
            }
            Ok(())
        } else {
            bail!("Something went wrong while removing account from configuration");
        }
    }

    pub fn remove_ca(&mut self, issuer_id: &str) -> Result<(), Error> {
        self.issuers
            .remove(issuer_id)
            .ok_or(anyhow::anyhow!("CA {issuer_id} not found"))?;
        config::save(&self.current_config()).context("Saving new configuration")?;
        Ok(())
    }

    pub async fn issue_new(&self, cert_config: CertificateConfiguration) -> Result<(), Error> {
        let cert_id = self.choose_cert_id_from_display_name(&cert_config.display_name);
        let authorizers = authorizers_from_config(cert_config.clone())?;
        let issuer = self
            .get_issuer_with_account(&cert_config.ca_identifier, &cert_config.account_identifier)?;
        let ca_name = &issuer.issuer.config.name;
        let key_type = cert_config.key_type;
        let cert_key = asymmetric::new_key(key_type)
            .and_then(asymmetric::KeyPair::to_rcgen_keypair)
            .context(format!(
                "Could not generate certificate key with type {key_type}"
            ))?;
        let cert = issuer
            .issue(&cert_key, cert_config.advanced.lifetime, authorizers)
            .await
            .context(format!("Issuing certificate with CA {ca_name}"))?;
        println!("Got a certificate!");
        config::save_certificate_and_config(&cert_id, &cert_config, &cert_key, &cert)?;
        Ok(())
    }

    pub async fn renew_certificate(
        &self,
        cert_id: &str,
        cert_config: &CertificateConfiguration,
        issuer: &AcmeIssuerWithAccount<'_>,
    ) -> IssueResult<()> {
        let inner_renewal_fn = async || {
            let cert_name = &cert_config.display_name;
            info!(
                "Renewing certificate {cert_name} at CA {}",
                issuer.issuer.config.name
            );
            let cert_key = if cert_config.advanced.reuse_key {
                let key_file = config::certificate_directory(cert_id).join("key.pem");
                asymmetric::KeyPair::load_from_disk(
                    File::open(key_file)
                        .context("Opening existing certificate private key file")?,
                )
                .context("Loading existing certificate private key file")?
                .to_rcgen_keypair()?
            } else {
                asymmetric::new_key(cert_config.key_type)?.to_rcgen_keypair()?
            };
            let authorizers = authorizers_from_config(cert_config.clone())?;
            let issue_result = issuer
                .issue(&cert_key, cert_config.advanced.lifetime, authorizers)
                .await;
            if let Ok(new_cert) = &issue_result {
                config::save_certificate_and_config(cert_id, cert_config, &cert_key, new_cert)?;
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
        };
        renewal_result.map(|_| ())
    }

    pub async fn print_accounts(&self) {
        let mut has_accounts = false;
        for issuer in self
            .issuers
            .values()
            .sorted_by_key(|issuer| issuer.config.name.clone())
        {
            if issuer.accounts.is_empty() {
                continue;
            }
            has_accounts = true;
            println!(
                "=== CA: Name: {}, ID: {} ===",
                issuer.config.name, issuer.config.identifier
            );
            for account_id in issuer
                .accounts
                .values()
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
            .sorted_by_key(|issuer| issuer.config.name.clone())
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
            .clone()
            .into_iter()
            .sorted_by_key(|(_, cert)| cert.display_name.clone())
        {
            println!("=== {} ===", cert.display_name);
            println!("ID: {cert_id}");
            println!("Domains: {}", cert.domains.keys().sorted().join(", "));
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

            let mut cert_file = config::certificate_directory(&cert_id);
            cert_file.push("fullchain.pem");
            match load_certificates_from_file(&cert_file, Some(1)) {
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

                        let not_after = cert
                            .validity
                            .not_after
                            .to_rfc2822()
                            .unwrap_or_else(|_| cert.validity.not_after.to_string());
                        let time_until_expired = cert.validity.time_to_expiration();
                        if let Some(time_until_expired) = time_until_expired {
                            let time_until_expired = util::humanize_duration(time_until_expired);
                            println!(
                                "Certificate is valid until: {not_after} (Expires in {time_until_expired})",
                            );
                        } else {
                            let now = time::OffsetDateTime::now_utc();
                            let expired_since = now - cert.validity.not_after.to_datetime();
                            let expired_since = util::humanize_duration(expired_since);
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
}

#[derive(Debug)]
pub struct AcmeIssuer {
    pub config: CertificateAuthorityConfiguration,
    client: OnceCell<AcmeClient>,
    accounts: HashMap<String, AcmeAccount>,
}

impl AcmeIssuer {
    pub fn try_new(config: CertificateAuthorityConfigurationWithAccounts) -> anyhow::Result<Self> {
        let client = OnceCell::new();
        let mut accounts = HashMap::new();
        for account_config in config.accounts {
            let account_id = account_config.identifier.clone();
            let account = AcmeAccount::load_existing(account_config)?;
            if let Some(old) = accounts.insert(account_id, account) {
                let id = old.config.identifier;
                bail!("Duplicate account id {id} in configuration");
            }
        }
        Ok(Self {
            client,
            accounts,
            config: config.inner,
        })
    }

    pub async fn client(&self) -> Result<&AcmeClient, Error> {
        self.client
            .get_or_try_init(|| async { new_acme_client(&self.config).await })
            .await
    }

    pub fn current_config(&self) -> CertificateAuthorityConfigurationWithAccounts {
        CertificateAuthorityConfigurationWithAccounts {
            inner: self.config.clone(),
            accounts: self
                .accounts
                .values()
                .map(|account| &account.config)
                .cloned()
                .collect(),
        }
    }

    pub fn with_account(&self, account_id: &str) -> Option<AcmeIssuerWithAccount> {
        let account = self.accounts.get(account_id)?;
        Some(AcmeIssuerWithAccount {
            issuer: self,
            account,
        })
    }

    pub fn get_account(&self, account_id: &str) -> Option<&AcmeAccount> {
        self.accounts.get(account_id)
    }

    pub fn add_account(&mut self, account: AcmeAccount) {
        self.accounts
            .insert(account.config.identifier.clone(), account);
    }

    pub fn remove_account(&mut self, account_id: &str) -> Option<AcmeAccount> {
        self.accounts.remove(account_id)
    }
}

#[derive(Debug, Clone)]
pub struct AcmeIssuerWithAccount<'a> {
    pub issuer: &'a AcmeIssuer,
    pub account: &'a AcmeAccount,
}

impl AcmeIssuerWithAccount<'_> {
    async fn client(&self) -> Result<&AcmeClient, Error> {
        self.issuer.client().await
    }

    pub async fn get_cert_from_finalized_order(
        &self,
        order: Order,
    ) -> IssueResult<DownloadedCertificate> {
        let certificate_url = order.certificate.ok_or(anyhow!(
            "CA did not provide a certificate URL for final order"
        ))?;
        debug!("Final certificate available @ {certificate_url}");
        let cert = self
            .client()
            .await?
            .download_certificate(&self.account.jwk, &certificate_url)
            .await
            .context("Downloading certificate")?;
        info!("Successfully issued a certificate!");
        Ok(cert)
    }

    pub async fn issue(
        &self,
        cert_key: &rcgen::KeyPair,
        cert_lifetime: Option<Duration>,
        authorizers: Vec<Authorizer>,
    ) -> IssueResult<DownloadedCertificate> {
        let identifiers: Vec<Identifier> = authorizers
            .iter()
            .map(|authorizer| authorizer.identifier.clone())
            .collect();
        let names = identifiers.join(", ");
        info!(
            "Issuing certificate for {names} at CA {}",
            self.issuer.config.name
        );
        let csr = create_and_sign_csr(cert_key, identifiers.clone())?;
        let (not_before, not_after) = match cert_lifetime {
            Some(lifetime) => {
                let not_before = current_time_truncated();
                let not_after = time::Duration::try_from(lifetime)
                    .and_then(|lifetime| not_before.checked_add(lifetime).ok_or(ConversionRange))
                    .context("Range error computing cert validity dates")
                    .client_failure()?;
                (Some(not_before), Some(not_after))
            }
            None => (None, None),
        };
        let request = NewOrderRequest {
            identifiers,
            not_before,
            not_after,
        };
        self.order_and_authorize(csr, request, authorizers).await
    }

    async fn order_and_authorize(
        &self,
        csr: CertificateSigningRequest,
        request: NewOrderRequest,
        authorizers: Vec<Authorizer>,
    ) -> IssueResult<DownloadedCertificate> {
        let client = self.client().await?;
        let (order_url, mut order) = client
            .new_order(&self.account.jwk, &request)
            .await
            .context("Error creating new order")?;
        debug!("Order URL: {}", order_url);
        match order.status {
            OrderStatus::Valid => {
                debug!("New order is already valid, downloading certificate");
                return self.get_cert_from_finalized_order(order).await;
            }
            OrderStatus::Processing => {
                debug!(
                    "New order is already processing, polling order and downloading certificate"
                );
                let final_order = client
                    .poll_order(&self.account.jwk, order, &order_url)
                    .await
                    .context("Polling finalized order")?;
                return self.get_cert_from_finalized_order(final_order).await;
            }
            OrderStatus::Ready => {
                debug!("New order is already ready, finalizing order");
                let final_order = client
                    .finalize_order(&self.account.jwk, &order, &csr)
                    .await
                    .context("Error finalizing order")?;
                return self.get_cert_from_finalized_order(final_order).await;
            }
            OrderStatus::Invalid => {
                if let Some(error) = order.error {
                    return Err(error.into());
                }
                return anyhow!("New order has unacceptable status (invalid)").ca_failure();
            }
            OrderStatus::Pending => {
                self.authorize(order, authorizers)
                    .await
                    .context("Error authorizing certificate issuance")
                    // TODO: Just because we failed 'during' authorization doesn't mean that the failure isn't
                    // something else. Only throw this if it's actually an acme::error::unauthorized issue
                    .authentication_failure()?;
                info!("Finished authorizing all identifiers");
            }
        }
        debug!("Re-fetching fully authorized order ({order_url})");
        order = client
            .get_order(&self.account.jwk, &order_url)
            .await
            .context("Re-fetching fully authorized order")?;
        match order.status {
            OrderStatus::Valid => {
                debug!("CA claims order is already valid, downloading certificate");
                self.get_cert_from_finalized_order(order).await
            }
            OrderStatus::Processing => {
                debug!(
                    "CA claims order is already processing, polling order and downloading certificate"
                );
                let final_order = client
                    .poll_order(&self.account.jwk, order, &order_url)
                    .await
                    .context("Polling finalized order")?;
                self.get_cert_from_finalized_order(final_order).await
            }
            OrderStatus::Ready => {
                debug!("Finalizing order");
                let final_order = client
                    .finalize_order(&self.account.jwk, &order, &csr)
                    .await
                    .context("Error finalizing order")?;
                self.get_cert_from_finalized_order(final_order).await
            }
            OrderStatus::Pending => {
                if let Some(error) = order.error {
                    return Err(error.into());
                }
                anyhow!("Order is still pending after having authorized all identifiers")
                    .ca_failure()
            }
            OrderStatus::Invalid => {
                if let Some(error) = order.error {
                    return Err(error.into());
                }
                anyhow!("Order has invalid status (no error reported by CA)").ca_failure()
            }
        }
    }

    async fn authorize(&self, order: Order, mut authorizers: Vec<Authorizer>) -> Result<(), Error> {
        let client = self.client().await?;
        for authz_url in order.authorizations {
            debug!("Checking authorization @ {authz_url}");
            let authz = client
                .get_authorization(&self.account.jwk, &authz_url)
                .await?;
            match authz.status {
                AuthorizationStatus::Valid => {
                    debug!("Authorization already valid");
                    // Skip
                }
                AuthorizationStatus::Pending => {
                    let id = authz.identifier;
                    info!("Found pending authorization for {id}, trying to authorize");
                    let mut challenge_solver =
                        authorizers.swap_remove(authorizers.iter().position(|authorizer| authorizer.identifier == id).ok_or(
                            anyhow!(
                                "Order contains pending authorization for {id}, but this identifier was not part of our requested order"
                            ),
                        )?);
                    let solver_name_long = challenge_solver.solver.long_name();
                    let solver_name_short = challenge_solver.solver.short_name();
                    let chosen_challenge = authz
                        .challenges
                        .into_iter()
                        .filter(|challenge| matches!(challenge.status, ChallengeStatus::Pending))
                        .filter(|challenge| !matches!(challenge.inner_challenge, InnerChallenge::Unknown))
                        .find(|challenge| challenge_solver.solver.supports_challenge(&challenge.inner_challenge))
                        .ok_or(anyhow!(
                            "Authorization for {id} did not contain any pending challenge supported by {solver_name_long}"
                        ))?;
                    let challenge_type = chosen_challenge.inner_challenge.get_type().to_string();
                    debug!(
                        "{solver_name_short} selected {challenge_type} challenge @ {}",
                        chosen_challenge.url
                    );

                    // TODO: Timeout solver?

                    // Setup
                    challenge_solver
                        .solver
                        .deploy_challenge(&self.account.jwk, &id, chosen_challenge.inner_challenge)
                        .await
                        .context(format!(
                            "Setting up challenge solver {solver_name_long} for {id}"
                        ))?;

                    debug!(
                        "{solver_name_short} reported successful challenge deployment, attempting validation now"
                    );

                    // TODO: Preflight checks? By us or by solver?

                    // Validation
                    client
                        .validate_challenge(&self.account.jwk, &chosen_challenge.url)
                        .await
                        .context(format!(
                            "Error validating {challenge_type} challenge for {id} with challenge solver {solver_name_long}"
                        ))?;

                    info!("Successfully validated challenge for {id}");

                    // Cleanup
                    if let Err(e) = challenge_solver.solver.cleanup_challenge().await {
                        warn!(
                            "Challenge solver {solver_name_long} for {id} encountered an error during cleanup: {e:#}"
                        );
                    }
                }
                AuthorizationStatus::Invalid => {
                    let id = &authz.identifier;
                    let problems: Vec<Problem> = authz
                        .challenges
                        .into_iter()
                        .filter_map(|challenge| challenge.error)
                        .collect();
                    let mut problem_string = String::new();
                    for problem in problems {
                        problem_string.push('\n');
                        problem_string.push_str(&problem.to_string());
                    }
                    bail!(
                        "Failed to authorize {id}. The CA reported these problems: {problem_string}"
                    )
                }
                AuthorizationStatus::Deactivated
                | AuthorizationStatus::Expired
                | AuthorizationStatus::Revoked => {
                    let id = &authz.identifier;
                    bail!(
                        "Authorization for {id} is in an invalid status (deactivated, expired, or revoked)"
                    )
                }
            }
        }
        Ok(())
    }

    pub async fn deactivate_account(&self) -> Result<(), Error> {
        let client = self.client().await?;
        let deactivated_account = client
            .deactivate_account(&self.account.jwk, &self.account.config.url)
            .await?;
        if matches!(deactivated_account.status, AccountStatus::Deactivated) {
            Ok(())
        } else {
            bail!(
                "ACME account has invalid status {} after deactivation",
                deactivated_account.status
            )
        }
    }
}
