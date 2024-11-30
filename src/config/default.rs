use crate::config::{
    default_rpc_address, CertificateAuthorityConfiguration, ConfigBackend, Configuration,
};
use anyhow::Error;
use std::path::Path;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct DefaultConfig {}

impl DefaultConfig {
    pub fn get_config(&self) -> Configuration {
        Configuration {
            rpc_address: default_rpc_address(),
            ca_list: vec![
                CertificateAuthorityConfiguration {
                    name: "Let's Encrypt".to_string(),
                    identifier: "letsencrypt".to_string(),
                    acme_directory: Url::from_str("https://acme-v02.api.letsencrypt.org/directory")
                        .unwrap(),
                    public: true,
                    testing: false,
                    default: true,
                    accounts: vec![],
                },
                CertificateAuthorityConfiguration {
                    name: "Let's Encrypt Staging".to_string(),
                    identifier: "letsencrypt-staging".to_string(),
                    acme_directory: Url::from_str(
                        "https://acme-staging-v02.api.letsencrypt.org/directory",
                    )
                    .unwrap(),
                    public: true,
                    testing: true,
                    default: false,
                    accounts: vec![],
                },
                // TODO: ZeroSSL, Google, others...
            ],
            cert_list: vec![],
        }
    }
}

impl ConfigBackend for DefaultConfig {
    fn load<P: AsRef<Path>>(_file: P) -> Result<Configuration, Error> {
        Ok(Self::default().get_config())
    }

    fn save<P: AsRef<Path>>(_config: &Configuration, _file: P) -> Result<(), Error> {
        unimplemented!("default backend cannot save to file")
    }
}
