use crate::acme::client::DownloadedCertificate;
use crate::challenge_solver::{ChallengeSolver, NullSolver};
use crate::config::toml::TomlConfiguration;
use crate::crypto::asymmetric::KeyType;
use crate::magic::MagicHttpSolver;
use crate::pebble::ChallengeTestHttpSolver;
use crate::util::serde_helper::key_type_config_serializer;
use crate::CRATE_NAME;
use anyhow::Error;
use rcgen::KeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;
use x509_parser::nom::AsBytes;

mod toml;

#[cfg(target_os = "linux")]
pub fn get_default_config_directory() -> PathBuf {
    PathBuf::from("/etc/certonaut")
}

#[cfg(target_os = "windows")]
pub fn get_default_config_directory() -> PathBuf {
    let app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(app_data).join("certonaut")
}

pub static CONFIG_FILE: OnceLock<PathBuf> = OnceLock::<PathBuf>::new();

#[allow(clippy::module_name_repetitions)]
pub fn config_directory() -> &'static Path {
    CONFIG_FILE.get_or_init(get_default_config_directory)
}

#[allow(clippy::module_name_repetitions)]
pub trait ConfigBackend {
    fn certificate_storage(&self, id: &str) -> PathBuf;
    fn load_main(&self) -> Result<MainConfiguration, Error>;
    fn save_main(&self, config: &MainConfiguration) -> Result<(), Error>;

    fn load_certificate(&self, id: &str) -> Result<CertificateConfiguration, Error>;
    fn save_certificate(&self, id: &str, config: &CertificateConfiguration) -> Result<(), Error>;

    fn list_certificates(&self) -> Result<Vec<String>, Error>;
}

pub struct MultiFileConfigBackend<'a> {
    base_dir: &'a Path,
}

impl<'a> MultiFileConfigBackend<'a> {
    pub fn new(base_dir: &'a Path) -> Self {
        Self { base_dir }
    }

    fn certificate_path(&self, id: &str) -> PathBuf {
        self.base_dir.join("certs").join(id)
    }

    fn main_path(&self) -> &Path {
        self.base_dir
    }
}

impl ConfigBackend for MultiFileConfigBackend<'_> {
    fn certificate_storage(&self, id: &str) -> PathBuf {
        self.certificate_path(id)
    }

    fn load_main(&self) -> Result<MainConfiguration, Error> {
        let main_path = self.main_path();
        TomlConfiguration::load(main_path.join(format!("{CRATE_NAME}.toml")))
    }

    fn save_main(&self, config: &MainConfiguration) -> Result<(), Error> {
        let main_path = self.main_path();
        std::fs::create_dir_all(main_path)?;
        TomlConfiguration::save(config, main_path.join(format!("{CRATE_NAME}.toml")))
    }

    fn load_certificate(&self, id: &str) -> Result<CertificateConfiguration, Error> {
        let cert_path = self.certificate_path(id);
        TomlConfiguration::load(cert_path.join("config.toml"))
    }

    fn save_certificate(&self, id: &str, config: &CertificateConfiguration) -> Result<(), Error> {
        let cert_path = self.certificate_path(id);
        std::fs::create_dir_all(&cert_path)?;
        TomlConfiguration::save(config, cert_path.join("config.toml"))
    }

    fn list_certificates(&self) -> Result<Vec<String>, Error> {
        let mut certificates = Vec::new();
        let cert_dir = self.base_dir.join("certs");
        let cert_dir_iter = match std::fs::read_dir(&cert_dir) {
            Ok(iter) => iter,
            Err(e) => {
                return match e.kind() {
                    std::io::ErrorKind::NotFound => Ok(certificates),
                    _ => Err(e.into()),
                };
            }
        };
        for dir_entry in cert_dir_iter.filter_map(Result::ok) {
            if dir_entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false)
                && dir_entry.path().join("config.toml").exists()
            {
                if let Some(file_name) = dir_entry.file_name().to_str() {
                    certificates.push(file_name.to_owned());
                }
            }
        }
        Ok(certificates)
    }
}

pub struct ConfigurationManager<B: ConfigBackend> {
    backend: B,
}

impl<B: ConfigBackend> ConfigurationManager<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn load(&self) -> Result<Configuration, Error> {
        let main_config = self.backend.load_main()?;
        let cert_ids = self.backend.list_certificates()?;
        let certificates = cert_ids
            .into_iter()
            .map(|id| self.backend.load_certificate(&id).map(|cert| (id, cert)))
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Configuration {
            main: main_config,
            certificates,
        })
    }

    pub fn save(&self, config: &Configuration) -> Result<(), Error> {
        self.backend.save_main(&config.main)?;
        for (id, cert) in &config.certificates {
            self.backend.save_certificate(id, cert)?;
        }
        Ok(())
    }

    pub fn certificate_storage(&self, id: &str) -> PathBuf {
        self.backend.certificate_storage(id)
    }

    pub fn save_certificate_config(
        &self,
        id: &str,
        config: &CertificateConfiguration,
    ) -> Result<(), Error> {
        self.backend.save_certificate(id, config)?;
        Ok(())
    }

    pub fn save_certificate_key(&self, id: &str, key: &KeyPair) -> Result<(), Error> {
        let cert_dir = self.backend.certificate_storage(id);
        std::fs::create_dir_all(&cert_dir)?;
        let key_file = cert_dir.join("key.pem");
        let pem = key.serialize_pem();
        std::fs::write(&key_file, pem.as_bytes())?;
        Ok(())
    }

    pub fn save_downloaded_certificate(
        &self,
        id: &str,
        cert: &DownloadedCertificate,
    ) -> Result<(), Error> {
        let cert_dir = self.backend.certificate_storage(id);
        std::fs::create_dir_all(&cert_dir)?;
        let key_file = cert_dir.join("fullchain.pem");
        let pem = cert.pem.as_bytes();
        std::fs::write(&key_file, pem)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Configuration {
    pub main: MainConfiguration,
    pub certificates: HashMap<String, CertificateConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainConfiguration {
    #[serde(rename = "ca")]
    pub ca_list: Vec<CertificateAuthorityConfigurationWithAccounts>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthorityConfigurationWithAccounts {
    #[serde(flatten)]
    pub inner: CertificateAuthorityConfiguration,
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
    #[serde(rename = "name")]
    pub display_name: String,
    pub auto_renew: bool,
    #[serde(rename = "ca")]
    pub ca_identifier: String,
    #[serde(rename = "account")]
    pub account_identifier: String,
    #[serde(with = "key_type_config_serializer")]
    pub key_type: KeyType,
    pub domains: HashMap<String, String>,
    #[serde(rename = "solver")]
    pub solvers: HashMap<String, SolverConfiguration>,
    #[serde(flatten)]
    pub advanced: AdvancedCertificateConfiguration,
    // TODO: installer configuration
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedCertificateConfiguration {
    pub reuse_key: bool,
    pub lifetime: Option<Duration>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierConfiguration {
    pub domain: String,
    #[serde(rename = "solver")]
    pub solver_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum SolverConfiguration {
    Null(NullSolverConfiguration),
    PebbleHttp(PebbleHttpSolverConfiguration),
    MagicHttp(MagicHttpSolverConfiguration),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullSolverConfiguration {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebbleHttpSolverConfiguration {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicHttpSolverConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) validation_port: Option<u16>,
}

impl SolverConfiguration {
    pub fn to_solver(self) -> Result<Box<dyn ChallengeSolver>, Error> {
        Ok(match self {
            SolverConfiguration::Null(solver) => NullSolver::from_config(solver),
            SolverConfiguration::PebbleHttp(solver) => ChallengeTestHttpSolver::from_config(solver),
            SolverConfiguration::MagicHttp(solver) => MagicHttpSolver::try_from_config(solver)?,
        })
    }

    pub fn name(&self) -> &str {
        match self {
            SolverConfiguration::Null(_) => "null",
            SolverConfiguration::PebbleHttp(_) => "pebble-http",
            SolverConfiguration::MagicHttp(_) => "magic-http",
        }
    }
}

// TODO: Get rid of these globals and refactor logic to be suitable for usage in tests

pub fn load() -> Result<Configuration, Error> {
    let directory = config_directory();
    let exists = directory.exists();
    let manager = ConfigurationManager::new(MultiFileConfigBackend::new(directory));
    if exists {
        manager.load()
    } else {
        let default = DefaultConfig::default().get_config();
        manager.save(&default)?;
        Ok(default)
    }
}

pub fn save(config: &Configuration) -> Result<(), Error> {
    let directory = config_directory();
    let manager = ConfigurationManager::new(MultiFileConfigBackend::new(directory));
    manager.save(config)?;
    Ok(())
}

pub fn certificate_directory(cert_id: &str) -> PathBuf {
    let directory = config_directory();
    let manager = ConfigurationManager::new(MultiFileConfigBackend::new(directory));
    manager.certificate_storage(cert_id)
}

#[allow(clippy::module_name_repetitions)]
pub fn save_certificate_and_config(
    id: &str,
    cert_config: &CertificateConfiguration,
    keypair: &KeyPair,
    cert: &DownloadedCertificate,
) -> Result<(), Error> {
    let directory = config_directory();
    let manager = ConfigurationManager::new(MultiFileConfigBackend::new(directory));
    manager.save_certificate_config(id, cert_config)?;
    manager.save_certificate_key(id, keypair)?;
    manager.save_downloaded_certificate(id, cert)?;
    Ok(())
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct DefaultConfig {}

impl DefaultConfig {
    pub fn get_config(&self) -> Configuration {
        Configuration {
            main: MainConfiguration {
                ca_list: vec![
                    CertificateAuthorityConfigurationWithAccounts {
                        inner: CertificateAuthorityConfiguration {
                            name: "Let's Encrypt".to_string(),
                            identifier: "lets-encrypt".to_string(),
                            acme_directory: Url::from_str(
                                "https://acme-v02.api.letsencrypt.org/directory",
                            )
                            .unwrap(),
                            public: true,
                            testing: false,
                            default: true,
                        },
                        accounts: vec![],
                    },
                    CertificateAuthorityConfigurationWithAccounts {
                        inner: CertificateAuthorityConfiguration {
                            name: "Let's Encrypt Staging".to_string(),
                            identifier: "lets-encrypt-staging".to_string(),
                            acme_directory: Url::from_str(
                                "https://acme-staging-v02.api.letsencrypt.org/directory",
                            )
                            .unwrap(),
                            public: true,
                            testing: true,
                            default: false,
                        },
                        accounts: vec![],
                    },
                    // TODO: ZeroSSL, Google, others...
                ],
            },
            certificates: HashMap::default(),
        }
    }
}
