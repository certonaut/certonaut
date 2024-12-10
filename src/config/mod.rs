use crate::acme::object::Identifier;
use crate::config::default::DefaultConfig;
use crate::config::toml::TomlConfiguration;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use url::Url;

mod default;
mod toml;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    #[serde(rename = "ca")]
    pub ca_list: Vec<CertificateAuthorityConfiguration>,
    #[serde(default, rename = "cert", skip_serializing_if = "Vec::is_empty")]
    pub cert_list: Vec<CertificateConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthorityConfiguration {
    pub name: String,
    #[serde(rename = "id")]
    pub identifier: String,
    #[serde(rename = "acme_url")]
    pub acme_directory: Url,
    pub public: bool,
    pub testing: bool,
    pub default: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<AccountConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfiguration {
    pub name: String,
    #[serde(rename = "id")]
    pub identifier: String,
    #[serde(rename = "key")]
    pub key_file: PathBuf,
    pub url: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfiguration {
    pub id: String,
    #[serde(rename = "account")]
    pub account_identifier: String,
    // TODO: use own type, not acme object
    pub identifiers: Vec<Identifier>,
    // TODO: authenticator & installer configuration
}

pub trait ConfigBackend {
    fn load<P: AsRef<Path>>(file: P) -> Result<Configuration, anyhow::Error>;
    fn save<P: AsRef<Path>>(config: &Configuration, file: P) -> Result<(), anyhow::Error>;
}

pub fn load<P: AsRef<Path>>(file: P) -> Result<Configuration, anyhow::Error> {
    if file.as_ref().exists() {
        TomlConfiguration::load(file)
    } else {
        let default = DefaultConfig::load(&file)?;
        TomlConfiguration::save(&default, &file)?;
        Ok(default)
    }
}

pub fn save<P: AsRef<Path>>(config: &Configuration, file: P) -> Result<(), anyhow::Error> {
    TomlConfiguration::save(config, file)
}
