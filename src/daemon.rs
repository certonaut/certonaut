use crate::acme::client::AcmeClient;
use crate::config::{AccountConfiguration, CertificateAuthorityConfiguration, Configuration};
use crate::crypto::jws::JsonWebKey;
use crate::{acme, crypto};
use anyhow::{anyhow, bail, Context};
use parking_lot::RwLock;
use std::collections::hash_map::Values;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::iter::Cloned;
use std::sync::Arc;

#[derive(Debug)]
pub struct OrbiterService {
    acme: RwLock<AcmeService>,
}

impl OrbiterService {
    pub async fn try_new(config: Configuration) -> Result<OrbiterService, anyhow::Error> {
        let acme_service = AcmeService::default();
        let mut orbiter_service = OrbiterService {
            acme: RwLock::new(acme_service),
        };
        orbiter_service.load_config(config).await?;
        Ok(orbiter_service)
    }

    pub async fn load_config(&mut self, config: Configuration) -> Result<(), anyhow::Error> {
        let mut issuers = Vec::with_capacity(config.ca_list.len());
        for ca_config in config.ca_list {
            let ca_config_clone = ca_config.clone();
            let mut accounts = Vec::with_capacity(ca_config.accounts.len());
            for account_config in ca_config.accounts {
                accounts.push(AcmeAccount::try_new(account_config)?);
            }
            let name = ca_config.name;
            // TODO: Graceful handling of temporarily unreachable CAs?
            let issuer = AcmeIssuer::try_new(ca_config_clone, accounts)
                .await
                .context(format!("Establishing connection to CA {name}"))?;
            issuers.push(issuer);
        }
        let acme_service = AcmeService::try_new(issuers)?;
        self.acme = RwLock::new(acme_service);
        Ok(())
    }

    pub async fn list_certificate_authorities(&self) -> Vec<Arc<AcmeIssuer>> {
        let lock = self.acme.read();
        lock.get_issuers().map(|issuers| issuers).collect()
    }

    pub async fn list_accounts(&self, ca_id: &str) -> Result<AccountIterator, anyhow::Error> {
        let lock = self.acme.read();
        let ca = lock
            .get_issuer(ca_id)
            .ok_or(anyhow!("No such CA {ca_id}"))?;
        Ok(AccountIterator { arc: ca })
    }

    pub fn current_config(&self) -> Configuration {
        // Build config from current state
        todo!()
    }
}

#[derive(Debug, Default)]
pub struct AcmeService {
    issuers: HashMap<String, Arc<AcmeIssuer>>,
}

impl AcmeService {
    pub fn try_new(issuers: Vec<AcmeIssuer>) -> Result<Self, anyhow::Error> {
        let mut service = Self {
            issuers: HashMap::with_capacity(issuers.len()),
        };
        service.reload(issuers)?;
        Ok(service)
    }

    pub fn get_issuer(&self, id: &str) -> Option<Arc<AcmeIssuer>> {
        self.issuers.get(id).cloned()
    }

    pub fn get_issuers(&self) -> Cloned<Values<'_, String, Arc<AcmeIssuer>>> {
        self.issuers.values().cloned()
    }

    pub fn reload(&mut self, issuers: Vec<AcmeIssuer>) -> Result<(), anyhow::Error> {
        if let Some(conflict) = first_duplicate_id(&issuers) {
            bail!("Duplicate CA id {conflict}");
        }
        self.issuers.clear();
        self.issuers.shrink_to(issuers.len());
        for issuer in issuers {
            self.issuers
                .insert(issuer.get_id().to_string(), Arc::new(issuer));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AcmeIssuer {
    config: CertificateAuthorityConfiguration,
    client: AcmeClient,
    accounts: HashMap<String, AcmeAccount>,
}

impl AcmeIssuer {
    pub async fn try_new(
        config: CertificateAuthorityConfiguration,
        accounts: Vec<AcmeAccount>,
    ) -> Result<Self, anyhow::Error> {
        if let Some(conflict) = first_duplicate_id(&accounts) {
            bail!("Duplicate account identifier: {conflict}")
        }
        let client = acme::client::AcmeClientBuilder::new(config.acme_directory.clone())
            .try_build()
            .await?;
        let mut account_map = HashMap::with_capacity(accounts.len());
        for account in accounts {
            account_map.insert(account.get_id().to_string(), account);
        }
        let issuer = AcmeIssuer {
            config,
            client,
            accounts: account_map,
        };
        Ok(issuer)
    }

    pub fn get_accounts(&self) -> Values<String, AcmeAccount> {
        self.accounts.values()
    }

    pub fn get_configuration(&self) -> &CertificateAuthorityConfiguration {
        &self.config
    }
}

pub struct AccountIterator {
    arc: Arc<AcmeIssuer>,
}

impl AccountIterator {
    pub fn iter(&self) -> Values<'_, String, AcmeAccount> {
        self.arc.get_accounts()
    }
}

#[derive(Debug)]
pub struct AcmeAccount {
    config: AccountConfiguration,
    jwk: JsonWebKey,
}

impl AcmeAccount {
    pub fn try_new(config: AccountConfiguration) -> Result<Self, anyhow::Error> {
        let key_file = File::open(&config.key_file).context("Cannot find account key")?;
        let keypair = crypto::signing::KeyPair::load_from_disk(key_file)?;
        let jwk = JsonWebKey::new_existing(keypair, config.url.clone());
        Ok(Self { config, jwk })
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

impl Identifiable for AcmeIssuer {
    fn get_id(&self) -> &str {
        &self.config.identifier
    }
}

/// Checks whether all IDs in the given Vec are unique. If so, None is returned. If there are duplicate
/// ids in the Vec, the first conflicting ID is returned.
fn first_duplicate_id<T: Identifiable>(list: &Vec<T>) -> Option<&str> {
    let mut unique_ids = HashSet::new();
    list.iter()
        .find(|item| !unique_ids.insert(item.get_id()))
        .map(|item| item.get_id())
}
