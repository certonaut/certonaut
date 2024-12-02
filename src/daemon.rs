use crate::acme::client::{AccountRegisterOptions, AcmeClient};
use crate::acme::http::HttpClient;
use crate::acme::object::Directory;
use crate::config::{
    AccountConfiguration, CertificateAuthorityConfiguration, CertificateConfiguration,
    Configuration,
};
use crate::crypto::jws::JsonWebKey;
use crate::crypto::signing;
use crate::crypto::signing::{Curve, KeyType};
use crate::pebble::pebble_root;
use crate::rpc::service::NewAccountRequest;
use crate::{acme, config, rpc};
use anyhow::{anyhow, bail, Context, Error};
use aws_lc_rs::rsa::KeySize;
use parking_lot::RwLock as SyncRwLock;
use std::collections::hash_map::Values;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::iter::Cloned;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;
use url::Url;

#[derive(Debug)]
pub struct OrbiterService {
    acme: AsyncRwLock<AcmeService>,
    cert_list: Vec<CertificateConfiguration>,
    rpc_addr: SocketAddr,
}

impl OrbiterService {
    pub async fn load_from_config(config: Configuration) -> Result<OrbiterService, Error> {
        let acme_service = AcmeService::try_new(config.ca_list).await?;
        Ok(OrbiterService {
            acme: AsyncRwLock::new(acme_service),
            cert_list: config.cert_list,
            rpc_addr: config.rpc_address,
        })
    }

    async fn build_configuration(&self) -> Configuration {
        let lock = self.acme.read().await;
        let ca_list = lock.build_config().await;
        Configuration {
            rpc_address: self.rpc_addr.clone(),
            ca_list,
            cert_list: vec![],
        }
    }

    pub async fn get_issuer_or_error(&self, ca_id: &str) -> Result<Arc<AsyncRwLock<AcmeIssuer>>, Error> {
        let lock = self.acme.read().await;
        lock.get_issuer(ca_id).ok_or(anyhow!("No such CA {ca_id}"))
    }

    pub async fn list_certificate_authorities(&self) -> Vec<Arc<AsyncRwLock<AcmeIssuer>>> {
        let lock = self.acme.read().await;
        lock.get_issuers().collect()
    }

    pub async fn list_account_configs(
        &self,
        ca_id: &str,
    ) -> Result<Vec<AccountConfiguration>, Error> {
        let ca = self.get_issuer_or_error(ca_id).await?;
        let lock = ca.read().await;
        Ok(lock
            .get_accounts()
            .map(|account| account.get_config().clone())
            .collect())
    }

    pub async fn create_account(
        &self,
        request: NewAccountRequest,
    ) -> Result<AccountConfiguration, Error> {
        let account_config = {
            let ca = self.get_issuer_or_error(&request.ca_id).await?;
            let mut ca = ca.write().await;
            let account = ca.create_account(request).await?;
            let account_config = account.get_config().clone();
            ca.add_account(account)?;
            account_config
        };
        let new_config = self.build_configuration().await;
        config::save(&new_config, "orbiter.toml").context("Saving new configuration")?;
        Ok(account_config)
    }
}

#[derive(Debug)]
pub struct AcmeService {
    issuers: HashMap<String, Arc<AsyncRwLock<AcmeIssuer>>>,
}

impl AcmeService {
    pub async fn try_new(ca_list: Vec<CertificateAuthorityConfiguration>) -> Result<Self, Error> {
        let mut issuers = HashMap::with_capacity(ca_list.len());
        for ca_config in &ca_list {
            let issuer = AcmeIssuer::try_new(ca_config.clone()).await?;
            let id = issuer.get_id().to_string();
            if issuers.insert(id.clone(), Arc::new(AsyncRwLock::new(issuer))).is_some() {
                bail!("Duplicate CA id {id}");
            }
        }
        Ok(Self { issuers })
    }

    pub fn get_issuer(&self, id: &str) -> Option<Arc<AsyncRwLock<AcmeIssuer>>> {
        self.issuers.get(id).cloned()
    }

    pub fn get_issuers(&self) -> Cloned<Values<'_, String, Arc<AsyncRwLock<AcmeIssuer>>>> {
        self.issuers.values().cloned()
    }

    pub async fn reload(
        &mut self,
        ca_list: Vec<CertificateAuthorityConfiguration>,
    ) -> Result<(), Error> {
        *self = Self::try_new(ca_list).await?;
        Ok(())
    }

    pub async fn build_config(&self) -> Vec<CertificateAuthorityConfiguration> {
        let mut configs = Vec::with_capacity(self.issuers.len());
        for issuer in self.issuers.values() {
            let issuer = issuer.read().await;
            configs.push(issuer.build_configuration())
        }
        configs
    }
}

#[derive(Debug)]
pub struct AcmeIssuer {
    meta: CAMeta,
    client: AcmeClient,
    accounts: HashMap<String, AcmeAccount>,
}

impl AcmeIssuer {
    pub async fn try_new(config: CertificateAuthorityConfiguration) -> Result<Self, Error> {
        let mut accounts = Vec::with_capacity(config.accounts.len());
        for account_config in config.accounts {
            let name = account_config.identifier.clone();
            accounts.push(
                AcmeAccount::load_existing(account_config)
                    .context(format!("Loading ACME account {name}"))?,
            );
        }
        if let Some(conflict) = first_duplicate_id(accounts.iter()) {
            bail!("Duplicate account identifier: {conflict}")
        }

        let name = &config.name;
        // TODO: Temporary measure for easy pebble tests
        let http_client = HttpClient::try_new_with_custom_root(pebble_root()?)?;
        let client = acme::client::AcmeClientBuilder::new(config.acme_directory.clone())
            .with_http_client(http_client)
            // TODO: Graceful handling of temporarily unreachable CAs?
            .try_build()
            .await
            .context(format!("Establishing connection to CA {name}"))?;
        let mut account_map = HashMap::with_capacity(accounts.len());
        for account in accounts {
            account_map.insert(account.get_id().to_string(), account);
        }
        let issuer = AcmeIssuer {
            meta: CAMeta {
                name: config.name,
                identifier: config.identifier,
                acme_url: config.acme_directory,
                public: config.public,
                testing: config.testing,
                default: config.default,
            },
            client,
            accounts: account_map,
        };
        Ok(issuer)
    }

    fn choose_account_id(&self, name: &str) -> String {
        let lower_name = name.to_lowercase();
        let mut candidate_id;
        let mut i = 0;
        loop {
            candidate_id = format!("{lower_name}-{i}");
            if first_duplicate_id(self.accounts.values()).is_none() {
                break;
            }
            i += 1;
        }
        candidate_id
    }

    pub fn get_accounts(&self) -> Values<String, AcmeAccount> {
        self.accounts.values()
    }

    pub fn build_configuration(&self) -> CertificateAuthorityConfiguration {
        let account_config = self.get_accounts().map(|a| a.config.clone()).collect();
        CertificateAuthorityConfiguration {
            name: self.meta.name.clone(),
            identifier: self.meta.identifier.clone(),
            acme_directory: self.meta.acme_url.clone(),
            public: self.meta.public,
            testing: self.meta.testing,
            default: self.meta.default,
            accounts: account_config,
        }
    }

    pub fn get_directory(&self) -> &Directory {
        self.client.get_directory()
    }

    pub async fn create_account(&self, request: NewAccountRequest) -> Result<AcmeAccount, Error> {
        let mut contacts = Vec::with_capacity(request.contacts.len());
        for contact in &request.contacts {
            contacts.push(Url::try_from(contact.as_str()).context("Validating contact URL")?);
        }
        let key_type = request
            .key_type
            .and_then(|key_type| rpc::service::Keytype::from_str_name(&key_type));
        let key_type = match key_type {
            Some(rpc::service::Keytype::Rsa2048) => KeyType::Rsa(KeySize::Rsa2048),
            Some(rpc::service::Keytype::Rsa3072) => KeyType::Rsa(KeySize::Rsa3072),
            Some(rpc::service::Keytype::Rsa4096) => KeyType::Rsa(KeySize::Rsa4096),
            Some(rpc::service::Keytype::EcdsaP256) => KeyType::Ecdsa(Curve::P256),
            Some(rpc::service::Keytype::EcdsaP384) => KeyType::Ecdsa(Curve::P384),
            _ => KeyType::Ecdsa(Curve::P256),
        };
        let keypair = signing::new_key(key_type).context("Generating new account key")?;
        let mut account_name = request.name;
        if account_name.is_empty() {
            account_name = self.meta.identifier.clone();
        }
        let account_id = self.choose_account_id(&account_name);
        // TODO: Configurable key directory
        let key_path = format!("{account_id}.key");
        let key_path = Path::new(&key_path);
        let account_file = File::create_new(&key_path).context("Saving account key to file")?;
        keypair
            .save_to_disk(account_file)
            .context("Saving account key to file")?;
        let key_path = key_path
            .canonicalize()
            .context("Saving account key to file")?;

        let options = AccountRegisterOptions {
            key: keypair,
            contact: contacts,
            terms_of_service_agreed: request.terms_of_service_agreed,
        };
        let (jwk, url, _account) = match self
            .client
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

    pub fn add_account(&mut self, account: AcmeAccount) -> Result<(), Error> {
        let id = account.get_id().to_string();
        if let Some(original) = self.accounts.insert(id.clone(), account) {
            self.accounts
                .insert(original.get_id().to_string(), original);
            bail!("Duplicate account id: {id}");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CAMeta {
    pub name: String,
    pub identifier: String,
    pub acme_url: Url,
    pub public: bool,
    pub testing: bool,
    pub default: bool,
}

#[derive(Debug)]
pub struct AcmeAccount {
    config: AccountConfiguration,
    jwk: JsonWebKey,
}

impl AcmeAccount {
    pub fn load_existing(config: AccountConfiguration) -> Result<Self, anyhow::Error> {
        let key_file = File::open(&config.key_file).context("Cannot find account key")?;
        let keypair = signing::KeyPair::load_from_disk(key_file)?;
        let jwk = JsonWebKey::new_existing(keypair, config.url.clone());
        // TODO: Validate accounts at CA, retrieve metadata?
        Ok(Self { config, jwk })
    }

    fn new_account(config: AccountConfiguration, jwk: JsonWebKey) -> Self {
        Self { config, jwk }
    }

    pub fn get_config(&self) -> &AccountConfiguration {
        &self.config
    }
}

pub trait Identifiable {
    fn get_id(&self) -> &str;
}

impl Identifiable for AcmeAccount {
    fn get_id(&self) -> &str {
        &self.config.identifier
    }
}

impl Identifiable for &AcmeIssuer {
    fn get_id(&self) -> &str {
        &self.meta.identifier
    }
}

impl Identifiable for AcmeIssuer {
    fn get_id(&self) -> &str {
        &self.meta.identifier
    }
}

impl Identifiable for &AcmeAccount {
    fn get_id(&self) -> &str {
        &self.config.identifier
    }
}

impl Identifiable for Arc<AcmeIssuer> {
    fn get_id(&self) -> &str {
        &self.meta.identifier
    }
}

/// Checks whether all IDs in the given Vec are unique. If so, None is returned. If there are duplicate
/// ids in the Vec, the first conflicting ID is returned.
fn first_duplicate_id<'a, I, T: Identifiable + 'a>(mut list: I) -> Option<&'a str>
where
    I: Iterator<Item = &'a T>,
{
    let mut unique_ids = HashSet::new();
    list.find(|item| !unique_ids.insert(item.get_id()))
        .map(|item| item.get_id())
}
