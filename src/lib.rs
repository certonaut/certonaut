extern crate core;

use crate::acme::client::{AccountRegisterOptions, AcmeClient, DownloadedCertificate};
use crate::acme::error::Problem;
use crate::acme::http::HttpClient;
use crate::acme::object::{
    AuthorizationStatus, ChallengeStatus, Identifier, InnerChallenge, NewOrderRequest, Order, OrderStatus,
};
use crate::cert::ParsedX509Certificate;
use crate::challenge_solver::{ChallengeSolver, KeyAuthorization};
use crate::config::{
    config_directory, AccountConfiguration, CertificateAuthorityConfiguration,
    CertificateAuthorityConfigurationWithAccounts, CertificateConfiguration, Configuration, MainConfiguration,
    SolverConfiguration,
};
use crate::crypto::asymmetric;
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::crypto::jws::JsonWebKey;
use crate::pebble::pebble_root;
use anyhow::{anyhow, bail, Context, Error};
use aws_lc_rs::rsa::KeySize;
use clap::{Args, ValueEnum};
use itertools::Itertools;
use rcgen::CertificateSigningRequest;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use time::error::ConversionRange;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use url::Url;

pub mod acme;
pub mod cert;
pub mod challenge_solver;
pub mod config;
pub mod crypto;
pub mod interactive;
pub mod magic;
pub mod pebble;
pub mod renew;
pub mod util;

/// The name of the application
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// The maximum number of certificates we will parse in a PEM-array of certificates by default
const DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH: usize = 100;

#[derive(Debug, Args, Default)]
pub struct IssueCommand {
    /// ID of the CA to use
    #[clap(short, long)]
    ca: Option<String>,
    /// ID of the account to use
    #[clap(short, long)]
    account: Option<String>,
    /// Domain names to include in the certificate
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    domains: Option<Vec<String>>,
    /// The display name of the new certificate
    #[clap(long)]
    cert_name: Option<String>,
    /// Type of key for the certificate
    #[clap(short, long, default_value_t = CommandLineKeyType::default())]
    key_type: CommandLineKeyType,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CommandLineKeyType {
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
        write!(f, "{}", enum_value.get_name())
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

fn current_time_truncated() -> time::OffsetDateTime {
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap(/* unreachable */)
}

// TODO: must-staple option (Note: LE has deprecated it, so not exactly motivated to give this high priority)
fn create_and_sign_csr(
    cert_key: &rcgen::KeyPair,
    identifiers: Vec<Identifier>,
) -> Result<CertificateSigningRequest, Error> {
    let cert_params = rcgen::CertificateParams::new(identifiers.into_iter().map(Into::into).collect::<Vec<String>>())
        .context("CSR generation failed")?;
    let csr = cert_params.serialize_request(cert_key).context("Signing CSR failed")?;
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
    load_certificates_from_reader(reader, limit).context(format!("Parsing certificate {cert_file_display} failed"))
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
    for pem in
        x509_parser::pem::Pem::iter_from_reader(reader).take(limit.unwrap_or(DEFAULT_MAX_CERTIFICATE_CHAIN_LENGTH))
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

pub fn build_cert_config<'a, I>(
    name: String,
    key_type: KeyType,
    issuer: &AcmeIssuerWithAccount,
    authorizers: I,
) -> CertificateConfiguration
where
    I: Iterator<Item = &'a Authorizer>,
{
    let size_hint = authorizers.size_hint().0;
    let mut domains = HashMap::with_capacity(size_hint);
    let mut solvers: HashMap<String, SolverConfiguration> = HashMap::with_capacity(size_hint);
    for authorizer in authorizers {
        let solver_config = authorizer.solver.config();
        if let Some((key, _)) = solvers.iter().find(|(_key, value)| **value == solver_config) {
            domains.insert(authorizer.identifier.to_string(), key.to_string());
        } else {
            let base_solver_name = authorizer.solver.short_name().to_string();
            let mut i = 0;
            let mut solver_name = base_solver_name.clone();
            while solvers.contains_key(&solver_name) {
                i += 1;
                solver_name = format!("{base_solver_name}-{i}");
            }
            domains.insert(authorizer.identifier.to_string(), solver_name.clone());
            solvers.insert(solver_name, solver_config);
        }
    }
    CertificateConfiguration {
        display_name: name,
        auto_renew: true,
        ca_identifier: issuer.issuer.config.identifier.clone(),
        account_identifier: issuer.account.config.identifier.clone(),
        key_type,
        domains,
        solvers,
    }
}

pub fn authorizers_from_config(config: CertificateConfiguration) -> anyhow::Result<Vec<Authorizer>> {
    let size = config.domains.len();
    let mut authorizers = Vec::with_capacity(size);
    for (domain, solver) in config.domains.into_iter().sorted() {
        let id = Identifier::from(domain);
        if authorizers
            .iter()
            .any(|authorizer: &Authorizer| authorizer.identifier == id)
        {
            bail!("Duplicate domain {id} in config");
        }

        let solver_config = config
            .solvers
            .get(&solver)
            .cloned()
            .ok_or(anyhow!("Solver {solver} not found"))?;
        let solver = solver_config.to_solver()?;
        authorizers.push(Authorizer::new_boxed(id, solver));
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
        let key_file = File::open(key_path).context(format!("Cannot read account key {}", key_path.display()))?;
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

async fn new_acme_client(ca_config: &CertificateAuthorityConfiguration) -> Result<AcmeClient, Error> {
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
    cert_list: HashMap<String, CertificateConfiguration>,
}

impl Certonaut {
    pub fn try_new(config: Configuration) -> anyhow::Result<Self> {
        let mut issuers = HashMap::new();
        for ca in config.main.ca_list {
            let id = ca.inner.identifier.clone();
            let issuer = AcmeIssuer::try_new(ca)?;
            if let Some(old) = issuers.insert(id, issuer) {
                let id = old.config.identifier;
                bail!("Duplicate CA id {id} in configuration");
            };
        }
        Ok(Self {
            issuers,
            cert_list: config.certificates,
        })
    }

    pub fn get_ca(&self, id: &str) -> Option<&AcmeIssuer> {
        self.issuers.get(id)
    }

    pub fn get_ca_mut(&mut self, id: &str) -> Option<&mut AcmeIssuer> {
        self.issuers.get_mut(id)
    }

    pub fn get_issuer_with_account(&self, issuer: &str, account: &str) -> anyhow::Result<AcmeIssuerWithAccount> {
        self.get_ca(issuer)
            .ok_or(anyhow!("CA {issuer} not found"))?
            .with_account(account)
            .ok_or(anyhow!("Account {account} not found"))
    }

    pub fn current_config(&self) -> Configuration {
        Configuration {
            main: MainConfiguration {
                ca_list: self.issuers.values().map(AcmeIssuer::current_config).collect(),
            },
            certificates: self.cert_list.clone(),
        }
    }

    pub async fn create_account(client: &AcmeClient, options: NewAccountOptions) -> Result<AcmeAccount, Error> {
        let keypair = asymmetric::new_key(options.key_type).context("Generating new account key")?;
        let mut account_name = options.name;
        if account_name.is_empty() {
            account_name.clone_from(&options.identifier);
        }
        let account_id = options.identifier;
        let config_path = config_directory();
        let key_path = config_path.join("account_keys").join(format!("{account_id}.key"));
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).context("Creating account key directory")?;
        }
        let account_file = File::create_new(&key_path).context("Saving account key to file")?;
        keypair
            .save_to_disk(account_file)
            .context("Saving account key to file")?;
        let key_path = key_path.canonicalize().context("Saving account key to file")?;

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
        let ca = self.get_ca_mut(ca_id).ok_or(anyhow::anyhow!("CA {ca_id} not found"))?;
        ca.add_account(new_account);
        config::save(&self.current_config()).context("Saving new configuration")?;
        Ok(())
    }

    pub fn choose_ca_id_from_name(&self, friendly_name: &str) -> String {
        // TODO: Append -test if a test CA and name conflicts?
        let mut ca_id = friendly_name.trim().to_lowercase().replace(' ', "-");
        ca_id.retain(|c| c.is_ascii_alphanumeric());
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

    pub fn choose_cert_name_from_authorizers(&self, authorizers: &Vec<Authorizer>) -> String {
        for authorizer in authorizers {
            let name = authorizer.identifier.to_string();
            let test_id = cert_id_from_display_name(&name);
            if !self.cert_list.contains_key(&test_id) {
                return name;
            }
        }
        // No free name in authorizers, so try something else
        let base_name = if let Some(authorizer) = authorizers.first() {
            authorizer.identifier.to_string()
        } else {
            "default".to_string()
        };
        let mut i = 1;
        let mut name = base_name.clone();
        let mut test_id = cert_id_from_display_name(&name);
        while self.cert_list.contains_key(&test_id) {
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
        while self.cert_list.contains_key(&cert_id) {
            i += 1;
            cert_id = format!("{cert_id_base}-{i}");
        }
        cert_id
    }
}

#[derive(Debug)]
pub struct AcmeIssuer {
    pub config: CertificateAuthorityConfiguration,
    client: Arc<OnceCell<AcmeClient>>,
    accounts: HashMap<String, AcmeAccount>,
}

impl AcmeIssuer {
    pub fn try_new(config: CertificateAuthorityConfigurationWithAccounts) -> anyhow::Result<Self> {
        let client = Arc::new(OnceCell::new());
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
            accounts: self.accounts.values().map(|account| &account.config).cloned().collect(),
        }
    }

    pub fn with_account(&self, account_id: &str) -> Option<AcmeIssuerWithAccount> {
        let account = self.accounts.get(account_id)?;
        Some(AcmeIssuerWithAccount { issuer: self, account })
    }

    pub fn get_account(&self, account_id: &str) -> Option<&AcmeAccount> {
        self.accounts.get(account_id)
    }

    pub fn add_account(&mut self, account: AcmeAccount) {
        self.accounts.insert(account.config.identifier.clone(), account);
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

impl<'a> AcmeIssuerWithAccount<'a> {
    async fn client(&self) -> Result<&AcmeClient, Error> {
        self.issuer.client().await
    }

    pub async fn get_cert_from_finalized_order(&self, order: Order) -> Result<DownloadedCertificate, Error> {
        let certificate_url = order
            .certificate
            .ok_or(anyhow!("CA did not provide a certificate URL for final order"))?;
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
    ) -> Result<DownloadedCertificate, Error> {
        let identifiers: Vec<Identifier> = authorizers
            .iter()
            .map(|authorizer| authorizer.identifier.clone())
            .collect();
        let names = identifiers.join(", ");
        info!("Issuing certificate for {names}");
        let csr = create_and_sign_csr(cert_key, identifiers.clone())?;
        let (not_before, not_after) = match cert_lifetime {
            Some(lifetime) => {
                let not_before = current_time_truncated();
                let not_after = time::Duration::try_from(lifetime)
                    .and_then(|lifetime| not_before.checked_add(lifetime).ok_or(ConversionRange))
                    .context("Range error computing cert validity dates")?;
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
    ) -> Result<DownloadedCertificate, Error> {
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
                debug!("New order is already processing, polling order and downloading certificate");
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
                    bail!(error);
                }
                bail!("New order has unacceptable status (invalid)")
            }
            OrderStatus::Pending => {
                self.authorize(order, authorizers)
                    .await
                    .context("Error authorizing certificate issuance")?;
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
                debug!("CA claims order is already processing, polling order and downloading certificate");
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
                    bail!(error);
                }
                bail!("Order is still pending after having authorized all identifiers");
            }
            OrderStatus::Invalid => {
                if let Some(error) = order.error {
                    bail!(error);
                }
                bail!("Order has invalid status (no error reported by CA)");
            }
        }
    }

    async fn authorize(&self, order: Order, mut authorizers: Vec<Authorizer>) -> Result<(), Error> {
        let client = self.client().await?;
        for authz_url in order.authorizations {
            debug!("Checking authorization @ {authz_url}");
            let authz = client.get_authorization(&self.account.jwk, &authz_url).await?;
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
                    debug!(
                        "{solver_name_short} selected {} challenge @ {}",
                        chosen_challenge.inner_challenge.get_type(),
                        chosen_challenge.url
                    );

                    // TODO: Timeout solver?

                    // Setup
                    challenge_solver
                        .solver
                        .deploy_challenge(&self.account.jwk, &id, chosen_challenge.inner_challenge)
                        .await
                        .context(format!("Setting up challenge solver {solver_name_long} for {id}"))?;

                    debug!("{solver_name_short} reported successful challenge deployment, attempting validation now");

                    // TODO: Preflight checks? By us or by solver?

                    // Validation
                    client
                        .validate_challenge(&self.account.jwk, &chosen_challenge.url)
                        .await
                        .context(format!(
                            "Error validating challenge for {id} with challenge solver {solver_name_long}"
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
                    bail!("Failed to authorize {id}. The CA reported these problems: {problem_string}")
                }
                AuthorizationStatus::Deactivated | AuthorizationStatus::Expired | AuthorizationStatus::Revoked => {
                    let id = &authz.identifier;
                    bail!("Authorization for {id} is in an invalid status (deactivated, expired, or revoked)")
                }
            }
        }
        Ok(())
    }

    // TODO: Move to AcmeClient?
    #[deprecated(note = "Not needed for a normal issuance flow. Could become a troubleshooting helper")]
    async fn deactivate_order_authorizations(&self, order_url: &Url) -> Result<(), Error> {
        let client = self.client().await?;
        let order = client.get_order(&self.account.jwk, order_url).await?;
        for authz_url in order.authorizations {
            // The order object unfortunately doesn't tell us the current status of the authz.
            // To avoid roundtrips, we just deactivate all authzs, even the ones that can't be deactivated.
            // Therefore, do not bail on errors here - just continue trying to deactivate as many as we can.
            client
                .deactivate_authorization(&self.account.jwk, &authz_url)
                .await
                .ok();
        }
        Ok(())
    }
}
