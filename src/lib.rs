use crate::acme::client::{AccountRegisterOptions, AcmeClient};
use crate::acme::http::HttpClient;
use crate::config::{AccountConfiguration, CertificateAuthorityConfiguration, Configuration};
use crate::crypto::jws::JsonWebKey;
use crate::crypto::signing;
use crate::crypto::signing::KeyType;
use crate::pebble::pebble_root;
use anyhow::{bail, Context, Error};
use clap::Args;
use std::fmt::Display;
use std::fs::File;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use url::Url;

pub mod acme;
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

fn find_account_by_id(
    ca: &CertificateAuthorityConfiguration,
    id: &str,
) -> Option<AccountConfiguration> {
    ca.accounts
        .iter()
        .find(|acc| acc.identifier == *id)
        .cloned()
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
        self.config
            .ca_list
            .iter_mut()
            .find(|ca| ca.identifier == *id)
    }

    pub async fn create_account(
        client: &AcmeClient,
        options: NewAccountOptions,
    ) -> Result<AcmeAccount, Error> {
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

    pub fn select_ca_and_account<FCASelect, FAccSelect>(
        &mut self,
        preselected_ca: &Option<String>,
        preselected_account: &Option<String>,
        fallback_ca_selection: FCASelect,
        fallback_account_selection: FAccSelect,
    ) -> Result<(CaChoice, AccountChoice), Error>
    where
        FCASelect: FnOnce(&mut Self) -> Result<CaChoice, Error>,
        FAccSelect:
            FnOnce(&mut Self, &CertificateAuthorityConfiguration) -> Result<AccountChoice, Error>,
    {
        let ca = if let Some(ca_id) = preselected_ca {
            CaChoice::ExistingCa(
                self.find_ca_by_id(ca_id)
                    .ok_or(anyhow::anyhow!("CA {ca_id} not found"))?,
            )
        } else {
            fallback_ca_selection(self)?
        };
        let account = match &ca {
            CaChoice::NewCa => AccountChoice::NewAccount,
            CaChoice::ExistingCa(ca) => {
                if let Some(account_id) = preselected_account {
                    AccountChoice::ExistingAccount(
                        find_account_by_id(ca, account_id)
                            .ok_or(anyhow::anyhow!("Account {account_id} not found"))?,
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
        config::save(&self.config, CONFIG_FILE.get().unwrap())
            .context("Saving new configuration")?;
        Ok(())
    }

    pub fn save_new_account(
        &mut self,
        ca_id: &String,
        new_account: AccountConfiguration,
    ) -> Result<(), Error> {
        let ca = self
            .find_ca_by_id_mut(ca_id)
            .ok_or(anyhow::anyhow!("CA {ca_id} not found"))?;
        ca.accounts.push(new_account);
        config::save(&self.config, CONFIG_FILE.get().unwrap())
            .context("Saving new configuration")?;
        Ok(())
    }

    pub fn choose_ca_id_from_name(&self, friendly_name: &str) -> String {
        let mut ca_id = friendly_name.trim().to_lowercase().replace(" ", "");
        ca_id.retain(|c| c.is_ascii());
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
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => {
                self_ca.identifier == other_ca.identifier
            }
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
            (
                AccountChoice::ExistingAccount(self_acc),
                AccountChoice::ExistingAccount(other_acc),
            ) => self_acc.identifier == other_acc.identifier,
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
