use crate::acme::client::{AccountRegisterOptions, AcmeClient, DownloadedCertificate};
use crate::acme::error::Problem;
use crate::acme::http::HttpClient;
use crate::acme::object::{AuthorizationStatus, ChallengeStatus, Identifier, InnerChallenge, NewOrderRequest, Order, OrderStatus, Token};
use crate::challenge_solver::{ChallengeSolver, NullSolver};
use crate::config::{AccountConfiguration, CertificateAuthorityConfiguration, Configuration};
use crate::crypto::jws::JsonWebKey;
use crate::crypto::signing;
use crate::crypto::signing::KeyType;
use crate::pebble::pebble_root;
use anyhow::{anyhow, bail, Context, Error};
use async_trait::async_trait;
use clap::Args;
use rcgen::CertificateSigningRequest;
use std::fmt::Display;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use time::error::ConversionRange;
use tracing::{debug, warn};
use url::Url;

pub mod acme;
pub mod challenge_solver;
pub mod config;
pub mod crypto;
pub mod interactive;
pub mod pebble;
pub mod util;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub static CONFIG_FILE: OnceLock<PathBuf> = OnceLock::<PathBuf>::new();

#[derive(Debug, Args, Default)]
pub struct IssueCommand {
    /// ID of the CA to use
    #[clap(short, long)]
    ca: Option<String>,
    /// ID of the account to use
    #[clap(short, long)]
    account: Option<String>,
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
        let key_file = File::open(&config.key_file).context("Cannot find account key")?;
        let keypair = signing::KeyPair::load_from_disk(key_file)?;
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

fn find_account_by_id(ca: &CertificateAuthorityConfiguration, id: &str) -> Option<AccountConfiguration> {
    ca.accounts.iter().find(|acc| acc.identifier == *id).cloned()
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

fn current_time_truncated() -> time::OffsetDateTime {
    let now = time::OffsetDateTime::now_utc();
    // unwrap is unreachable due to const valid nanosecond
    now.replace_nanosecond(0).unwrap()
}

// TODO: must-staple option
fn create_and_sign_csr(cert_key: &rcgen::KeyPair, identifiers: Vec<Identifier>) -> Result<CertificateSigningRequest, Error> {
    let cert_params =
        rcgen::CertificateParams::new(identifiers.into_iter().map(Into::into).collect::<Vec<String>>()).context("CSR generation failed")?;
    let csr = cert_params.serialize_request(cert_key).context("Signing CSR failed")?;
    Ok(csr)
}

#[derive(Debug)]
pub struct Certonaut {
    config: Configuration,
}

impl Certonaut {
    pub fn new(config: Configuration) -> Self {
        Self { config }
    }

    fn find_ca_by_id(&self, id: &str) -> Option<CertificateAuthorityConfiguration> {
        self.config
            .ca_list
            .iter()
            .find(|ca| ca.identifier == *id)
            // TODO: Maybe let callers decide when to clone
            .cloned()
    }

    fn find_ca_by_id_mut(&mut self, id: &str) -> Option<&mut CertificateAuthorityConfiguration> {
        self.config.ca_list.iter_mut().find(|ca| ca.identifier == *id)
    }

    pub async fn create_account(client: &AcmeClient, options: NewAccountOptions) -> Result<AcmeAccount, Error> {
        let keypair = signing::new_key(options.key_type).context("Generating new account key")?;
        let mut account_name = options.name;
        if account_name.is_empty() {
            account_name = options.identifier.clone();
        }
        let account_id = options.identifier;
        // TODO: Configurable key directory
        let key_path = format!("{account_id}.key");
        let key_path = Path::new(&key_path);
        let account_file = File::create_new(key_path).context("Saving account key to file")?;
        keypair.save_to_disk(account_file).context("Saving account key to file")?;
        let key_path = key_path.canonicalize().context("Saving account key to file")?;

        let options = AccountRegisterOptions {
            key: keypair,
            contact: options.contacts,
            terms_of_service_agreed: options.terms_of_service_agreed,
        };
        let (jwk, url, _account) = match client.register_account(options).await.context("Registering account at CA failed") {
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

    pub fn select_ca_and_account<FCASelect, FAccSelect>(
        &mut self,
        preselected_ca: &Option<String>,
        preselected_account: &Option<String>,
        fallback_ca_selection: FCASelect,
        fallback_account_selection: FAccSelect,
    ) -> Result<(CaChoice, AccountChoice), Error>
    where
        FCASelect: FnOnce(&mut Self) -> Result<CaChoice, Error>,
        FAccSelect: FnOnce(&mut Self, &CertificateAuthorityConfiguration) -> Result<AccountChoice, Error>,
    {
        let ca = if let Some(ca_id) = preselected_ca {
            CaChoice::ExistingCa(self.find_ca_by_id(ca_id).ok_or(anyhow::anyhow!("CA {ca_id} not found"))?)
        } else {
            fallback_ca_selection(self)?
        };
        let account = match &ca {
            CaChoice::NewCa => AccountChoice::NewAccount,
            CaChoice::ExistingCa(ca) => {
                if let Some(account_id) = preselected_account {
                    AccountChoice::ExistingAccount(
                        find_account_by_id(ca, account_id).ok_or(anyhow::anyhow!("Account {account_id} not found"))?,
                    )
                } else {
                    fallback_account_selection(self, ca)?
                }
            }
        };
        Ok((ca, account))
    }

    pub fn save_new_ca(&mut self, new_ca: CertificateAuthorityConfiguration) -> Result<(), Error> {
        self.config.ca_list.push(new_ca);
        config::save(&self.config, CONFIG_FILE.get().unwrap()).context("Saving new configuration")?;
        Ok(())
    }

    pub fn save_new_account(&mut self, ca_id: &String, new_account: AccountConfiguration) -> Result<(), Error> {
        let ca = self.find_ca_by_id_mut(ca_id).ok_or(anyhow::anyhow!("CA {ca_id} not found"))?;
        ca.accounts.push(new_account);
        config::save(&self.config, CONFIG_FILE.get().unwrap()).context("Saving new configuration")?;
        Ok(())
    }

    pub fn choose_ca_id_from_name(&self, friendly_name: &str) -> String {
        let mut ca_id = friendly_name.trim().to_lowercase().replace(" ", "-");
        ca_id.retain(|c| c.is_ascii_alphanumeric());
        let mut ca_num = self.config.ca_list.len();
        if ca_id.is_empty() {
            ca_id = format!("ca-{ca_num}");
        }
        let ca_id_base = ca_id.clone();
        while self.find_ca_by_id(&ca_id).is_some() {
            ca_num += 1;
            ca_id = format!("{ca_id_base}-{ca_num}");
        }
        ca_id
    }
}

#[derive(Debug, Clone)]
pub enum CaChoice {
    ExistingCa(CertificateAuthorityConfiguration),
    NewCa,
}

impl PartialEq for CaChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => self_ca.identifier == other_ca.identifier,
            _ => false,
        }
    }
}

impl Display for CaChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaChoice::ExistingCa(ca) => {
                let name = &ca.name;
                write!(f, "{name}")?;
                if ca.testing {
                    write!(f, " (Testing)")?
                };
            }
            CaChoice::NewCa => write!(f, "Add new CA")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum AccountChoice {
    ExistingAccount(AccountConfiguration),
    NewAccount,
}

impl PartialEq for AccountChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AccountChoice::ExistingAccount(self_acc), AccountChoice::ExistingAccount(other_acc)) => {
                self_acc.identifier == other_acc.identifier
            }
            _ => false,
        }
    }
}

impl Display for AccountChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountChoice::ExistingAccount(ca) => {
                let name = &ca.name;
                write!(f, "{name}")?;
            }
            AccountChoice::NewAccount => write!(f, "Create new account")?,
        }
        Ok(())
    }
}

pub struct AcmeIssuer {
    client: Arc<AcmeClient>,
    account: AcmeAccount,
}

impl AcmeIssuer {
    pub fn new(client: Arc<AcmeClient>, account: AcmeAccount) -> Self {
        Self { client, account }
    }

    pub async fn get_cert_from_finalized_order(&self, order: Order) -> Result<DownloadedCertificate, Error> {
        let certificate_url = order
            .certificate
            .ok_or(anyhow!("CA did not provide a certificate URL for final order"))?;
        let cert = self
            .client
            .download_certificate(&self.account.jwk, &certificate_url)
            .await
            .context("Downloading certificate")?;
        Ok(cert)
    }

    pub async fn issue(
        // TODO: Do we need &mut?
        &mut self,
        cert_key: &rcgen::KeyPair,
        cert_lifetime: Option<Duration>,
        mut authorizers: Vec<Authorizer>,
    ) -> Result<DownloadedCertificate, Error> {
        let identifiers: Vec<Identifier> = authorizers.iter().map(|authorizer| authorizer.identifier.clone()).collect();
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
        let (order_url, mut order) = self
            .client
            .new_order(&self.account.jwk, &request)
            .await
            .context("Creating new order")?;
        debug!("Order URL: {}", order_url);
        // TODO: Deadline issuance process
        loop {
            match order.status {
                OrderStatus::Valid => {
                    return self.get_cert_from_finalized_order(order).await;
                }
                OrderStatus::Processing => {
                    let final_order = self.client.poll_order(&self.account.jwk, order, &order_url).await?;
                    return self.get_cert_from_finalized_order(final_order).await;
                }
                OrderStatus::Ready => {
                    let final_order = self.client.finalize_order(&self.account.jwk, &order, &csr).await?;
                    return self.get_cert_from_finalized_order(final_order).await;
                }
                OrderStatus::Invalid => bail!("New order has unacceptable status (invalid)"),
                OrderStatus::Pending => {
                    // Go authorize
                }
            }
            for authz_url in order.authorizations {
                let authz = self.client.get_authorization(&self.account.jwk, &authz_url).await?;
                match authz.status {
                    AuthorizationStatus::Valid => {
                        // Skip
                    }
                    AuthorizationStatus::Pending => {
                        let id = authz.identifier;
                        let mut challenge_solver =
                            authorizers.swap_remove(authorizers.iter().position(|authorizer| authorizer.identifier == id).ok_or(
                                anyhow!(
                                "Order contains pending authorization for {id}, but this identifier was not part of our requested order"
                            ),
                            )?);
                        let chosen_challenge = authz
                            .challenges
                            .into_iter()
                            .filter(|challenge| matches!(challenge.status, ChallengeStatus::Pending))
                            .filter(|challenge| !matches!(challenge.inner_challenge, InnerChallenge::Unknown))
                            .find(|challenge| challenge_solver.solver.supports_challenge(&challenge.inner_challenge))
                            // TODO: Describe solver in error message
                            .ok_or(anyhow!(
                                "Authorization for {id} did not contain any pending challenge supported by solver"
                            ))?;

                        // TODO: Timeout solver

                        // Setup
                        challenge_solver
                            .solver
                            .deploy_challenge(&self.account.jwk, &id, chosen_challenge.inner_challenge)
                            .await
                            .context(format!("Setting up challenge solver for {id}"))?;

                        // Validation
                        self.client.validate_challenge(&self.account.jwk, &chosen_challenge.url).await?;

                        // Cleanup
                        if let Err(e) = challenge_solver.solver.cleanup_challenge().await {
                            warn!("Challenge solver for {id} encountered an error during cleanup: {e:#}");
                        }
                    }
                    AuthorizationStatus::Invalid => {
                        let id = &authz.identifier;
                        let problems: Vec<Problem> = authz.challenges.into_iter().filter_map(|challenge| challenge.error).collect();
                        let mut problem_string = String::new();
                        problems.into_iter().for_each(|problem| {
                            problem_string.push('\n');
                            problem_string.push_str(&problem.to_string())
                        });
                        bail!("Failed to authorize {id}. The CA reported these problems: {problem_string}")
                    }
                    AuthorizationStatus::Deactivated | AuthorizationStatus::Expired | AuthorizationStatus::Revoked => {
                        let id = &authz.identifier;
                        bail!("Authorization for {id} is in an invalid status (deactivated, expired, or revoked)")
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            order = self.client.get_order(&self.account.jwk, &order_url).await?
        }
    }
}

pub struct Authorizer {
    identifier: Identifier,
    solver: Box<dyn ChallengeSolver>,
}
