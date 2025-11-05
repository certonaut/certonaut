use crate::acme::client::DownloadedCertificate;
use crate::cert::{ParsedX509Certificate, load_certificates_from_file};
use crate::challenge_solver::{ChallengeSolver, NullSolver, WebrootSolver};
use crate::config::toml::TomlConfiguration;
use crate::crypto::asymmetric::{KeyPair, KeyType};
use crate::dns::solver::acme_dns;
use crate::magic::MagicHttpSolver;
use crate::pebble::ChallengeTestHttpSolver;
use crate::util::serde_helper::key_type_config_serializer;
use crate::{CRATE_NAME, Identifier};
use anyhow::{Context, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;
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
    fn load_main(&self) -> Result<MainConfiguration, Error>;
    fn save_main(&self, config: &MainConfiguration) -> Result<(), Error>;
    fn load_certificate_config(&self, id: &str) -> Result<CertificateConfiguration, Error>;
    fn load_certificate_private_key(&self, id: &str) -> Result<KeyPair, Error>;
    fn load_certificate_files(
        &self,
        id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ParsedX509Certificate>, Error>;
    fn save_certificate_config(
        &self,
        id: &str,
        config: &CertificateConfiguration,
    ) -> Result<(), Error>;
    fn save_certificate_private_key(&self, id: &str, key: &KeyPair) -> Result<(), Error>;
    fn save_certificate_file(&self, id: &str, cert: &DownloadedCertificate) -> Result<(), Error>;
    fn list_certificates(&self) -> Result<Vec<String>, Error>;
    fn certificate_directory(&self, id: &str) -> PathBuf;
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
    fn load_main(&self) -> Result<MainConfiguration, Error> {
        let main_path = self.main_path();
        TomlConfiguration::load(main_path.join(format!("{CRATE_NAME}.toml")))
    }

    fn save_main(&self, config: &MainConfiguration) -> Result<(), Error> {
        let main_path = self.main_path();
        std::fs::create_dir_all(main_path)?;
        TomlConfiguration::save(config, main_path.join(format!("{CRATE_NAME}.toml")))
    }

    fn load_certificate_config(&self, id: &str) -> Result<CertificateConfiguration, Error> {
        let cert_path = self.certificate_path(id);
        TomlConfiguration::load(cert_path.join("config.toml"))
    }

    fn load_certificate_private_key(&self, id: &str) -> Result<KeyPair, Error> {
        let cert_path = self.certificate_path(id);
        let key_file = cert_path.join("privkey.pem");
        KeyPair::load_from_disk(
            File::open(&key_file)
                .context(format!("Opening private key file {}", key_file.display()))?,
        )
        .context(format!("Loading private key {}", key_file.display()))
    }

    fn load_certificate_files(
        &self,
        id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ParsedX509Certificate>, Error> {
        let cert_path = self.certificate_path(id);
        let cert_file = cert_path.join("fullchain.pem");
        load_certificates_from_file(cert_file, limit)
    }

    fn save_certificate_config(
        &self,
        id: &str,
        config: &CertificateConfiguration,
    ) -> Result<(), Error> {
        let cert_path = self.certificate_path(id);
        std::fs::create_dir_all(&cert_path)?;
        TomlConfiguration::save(config, cert_path.join("config.toml"))
    }

    fn save_certificate_private_key(&self, id: &str, key: &KeyPair) -> Result<(), Error> {
        let cert_path = self.certificate_path(id);
        std::fs::create_dir_all(&cert_path).context(format!(
            "Creating directory for certificate private key file {}",
            cert_path.display()
        ))?;
        let key_file = cert_path.join("privkey.pem");
        let key_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&key_file)
            .context(format!("Opening private key file {}", key_file.display()))?;
        key.save_to_disk(key_file)?;
        Ok(())
    }

    fn save_certificate_file(&self, id: &str, cert: &DownloadedCertificate) -> Result<(), Error> {
        let cert_path = self.certificate_path(id);
        std::fs::create_dir_all(&cert_path).context(format!(
            "Creating directory for certificate file {}",
            cert_path.display()
        ))?;
        let cert_file = cert_path.join("fullchain.pem");
        let pem = cert.pem.as_bytes();
        std::fs::write(&cert_file, pem).context(format!(
            "Writing certificate to file {}",
            cert_file.display()
        ))?;
        Ok(())
    }

    fn list_certificates(&self) -> Result<Vec<String>, Error> {
        let mut certificates = Vec::new();
        let cert_dir = self.base_dir.join("certs");
        let cert_dir_iter = match std::fs::read_dir(&cert_dir) {
            Ok(iter) => iter,
            Err(e) => {
                return match e.kind() {
                    ErrorKind::NotFound => Ok(certificates),
                    _ => Err(Error::new(e).context("Listing certificate directory")),
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

    fn certificate_directory(&self, id: &str) -> PathBuf {
        self.certificate_path(id)
    }
}

#[derive(Debug)]
pub struct ConfigurationManager<B> {
    backend: B,
}

impl<B: ConfigBackend> ConfigurationManager<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn load(&self) -> Result<Configuration, Error> {
        let main_config = match self.backend.load_main() {
            Ok(main_config) => main_config,
            Err(e) => {
                if let Some(io_error) = e.downcast_ref::<std::io::Error>() {
                    match io_error.kind() {
                        ErrorKind::NotFound => {
                            // Assume no config exists - overwrite with default
                            let default = DefaultConfig::default().get_config();
                            self.save_all(&default)?;
                            self.backend.load_main()?
                        }
                        _ => {
                            return Err(e);
                        }
                    }
                } else {
                    return Err(e);
                }
            }
        };
        let cert_ids = self.backend.list_certificates()?;
        let certificates = cert_ids
            .into_iter()
            .map(|id| {
                self.backend
                    .load_certificate_config(&id)
                    .map(|cert| (id, cert))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Configuration {
            main: main_config,
            certificates,
        })
    }

    pub fn save_main(&self, config: &MainConfiguration) -> Result<(), Error> {
        self.backend.save_main(config)
    }

    pub fn save_all(&self, config: &Configuration) -> Result<(), Error> {
        self.save_main(&config.main)?;
        for (id, cert) in &config.certificates {
            self.backend.save_certificate_config(id, cert)?;
        }
        Ok(())
    }

    pub fn load_certificate_files(
        &self,
        id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ParsedX509Certificate>, Error> {
        self.backend.load_certificate_files(id, limit)
    }

    pub fn load_certificate_private_key(&self, id: &str) -> Result<KeyPair, Error> {
        self.backend.load_certificate_private_key(id)
    }

    pub fn save_certificate_config(
        &self,
        id: &str,
        config: &CertificateConfiguration,
    ) -> Result<(), Error> {
        self.backend.save_certificate_config(id, config)?;
        Ok(())
    }

    pub fn save_certificate_private_key(&self, id: &str, key: &KeyPair) -> Result<(), Error> {
        self.backend.save_certificate_private_key(id, key)
    }

    pub fn save_downloaded_certificate(
        &self,
        id: &str,
        cert: &DownloadedCertificate,
    ) -> Result<(), Error> {
        self.backend.save_certificate_file(id, cert)
    }

    pub fn save_certificate_and_config(
        &self,
        id: &str,
        cert_config: &CertificateConfiguration,
        keypair: &KeyPair,
        cert: &DownloadedCertificate,
    ) -> Result<(), Error> {
        self.save_certificate_config(id, cert_config)?;
        self.save_certificate_private_key(id, keypair)?;
        self.save_downloaded_certificate(id, cert)?;
        Ok(())
    }

    pub fn certificate_directory(&self, cert_id: &str) -> PathBuf {
        self.backend.certificate_directory(cert_id)
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_roots: Vec<PathBuf>,
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
    #[serde(flatten)]
    pub domains_and_solvers: DomainSolverMap,
    #[serde(flatten)]
    pub advanced: AdvancedCertificateConfiguration,
    #[serde(default)]
    pub installer: Option<InstallerConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSolverMap {
    pub domains: HashMap<Identifier, String>,
    #[serde(rename = "solver")]
    pub solvers: HashMap<String, SolverConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedCertificateConfiguration {
    pub reuse_key: bool,
    pub lifetime_seconds: Option<u64>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierConfiguration {
    pub domain: Identifier,
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
    Webroot(WebrootSolverConfiguration),
    AcmeDns(AcmeDnsConfiguration),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullSolverConfiguration {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebbleHttpSolverConfiguration {
    pub base_url: Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicHttpSolverConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebrootSolverConfiguration {
    pub webroot: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeDnsConfiguration {
    #[serde(flatten)]
    pub registration: acme_dns::Registration,
    pub server: Url,
}

impl SolverConfiguration {
    pub fn to_solver(self) -> Result<Box<dyn ChallengeSolver>, Error> {
        Ok(match self {
            SolverConfiguration::Null(solver) => NullSolver::from_config(solver),
            SolverConfiguration::PebbleHttp(solver) => ChallengeTestHttpSolver::from_config(solver),
            SolverConfiguration::MagicHttp(solver) => MagicHttpSolver::try_from_config(solver)?,
            SolverConfiguration::Webroot(solver) => WebrootSolver::from_config(solver),
            SolverConfiguration::AcmeDns(solver) => acme_dns::Solver::try_from_config(solver)?,
        })
    }

    pub fn name(&self) -> &str {
        match self {
            SolverConfiguration::Null(_) => "null",
            SolverConfiguration::PebbleHttp(_) => "pebble-http",
            SolverConfiguration::MagicHttp(_) => "magic-http",
            SolverConfiguration::Webroot(_) => "webroot",
            SolverConfiguration::AcmeDns(_) => "acme-dns",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InstallerConfiguration {
    Script { script: String },
}

pub fn new_configuration_manager_with_default_config()
-> Result<ConfigurationManager<MultiFileConfigBackend<'static>>, Error> {
    let directory = config_directory();
    let manager = ConfigurationManager::new(MultiFileConfigBackend::new(directory));
    Ok(manager)
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct DefaultConfig {}

impl DefaultConfig {
    #[allow(clippy::missing_panics_doc)]
    pub fn get_config(&self) -> Configuration {
        Configuration {
            main: MainConfiguration {
                ca_list: vec![
                    CertificateAuthorityConfiguration {
                        name: "Let's Encrypt".to_string(),
                        identifier: "letsencrypt".to_string(),
                        acme_directory: Url::from_str(
                            "https://acme-v02.api.letsencrypt.org/directory",
                        )
                        .unwrap(),
                        public: true,
                        testing: false,
                        default: true,
                        trusted_roots: vec![],
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
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "Google".to_string(),
                        identifier: "google".to_string(),
                        acme_directory: Url::from_str("https://dv.acme-v02.api.pki.goog/directory")
                            .unwrap(),
                        public: true,
                        testing: false,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "Google Staging".to_string(),
                        identifier: "google-staging".to_string(),
                        acme_directory: Url::from_str(
                            "https://dv.acme-v02.test-api.pki.goog/directory",
                        )
                        .unwrap(),
                        public: true,
                        testing: true,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "BuyPass".to_string(),
                        identifier: "buypass".to_string(),
                        acme_directory: Url::from_str("https://api.buypass.com/acme/directory")
                            .unwrap(),
                        public: true,
                        testing: false,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "BuyPass Test".to_string(),
                        identifier: "buypass-test".to_string(),
                        acme_directory: Url::from_str(
                            "https://api.test4.buypass.no/acme/directory",
                        )
                        .unwrap(),
                        public: true,
                        testing: true,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "ZeroSSL".to_string(),
                        identifier: "zerossl".to_string(),
                        acme_directory: Url::from_str("https://acme.zerossl.com/v2/DV90").unwrap(),
                        public: true,
                        testing: false,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "SSL.com ECC".to_string(),
                        identifier: "ssl.com-ecc".to_string(),
                        acme_directory: Url::from_str("https://acme.ssl.com/sslcom-dv-ecc")
                            .unwrap(),
                        public: true,
                        testing: false,
                        default: false,
                        trusted_roots: vec![],
                    },
                    CertificateAuthorityConfiguration {
                        name: "SSL.com RSA".to_string(),
                        identifier: "ssl.com-rsa".to_string(),
                        acme_directory: Url::from_str("https://acme.ssl.com/sslcom-dv-rsa")
                            .unwrap(),
                        public: true,
                        testing: false,
                        default: false,
                        trusted_roots: vec![],
                    },
                ]
                .into_iter()
                .map(|config| CertificateAuthorityConfigurationWithAccounts {
                    inner: config,
                    accounts: Vec::new(),
                })
                .collect(),
            },
            certificates: HashMap::default(),
        }
    }
}

pub mod test_backend {
    use crate::acme::client::DownloadedCertificate;
    use crate::cert::ParsedX509Certificate;
    use crate::config::{
        CertificateConfiguration, ConfigBackend, ConfigurationManager, MainConfiguration,
    };
    use crate::crypto::asymmetric::KeyPair;
    use anyhow::Error;
    use std::path::PathBuf;

    pub fn new_configuration_manager_with_noop_backend() -> ConfigurationManager<NoopBackend> {
        ConfigurationManager::new(NoopBackend {})
    }

    pub struct NoopBackend {}

    impl ConfigBackend for NoopBackend {
        fn load_main(&self) -> Result<MainConfiguration, Error> {
            Ok(MainConfiguration { ca_list: vec![] })
        }

        fn save_main(&self, _config: &MainConfiguration) -> Result<(), Error> {
            Ok(())
        }

        fn load_certificate_config(&self, _id: &str) -> Result<CertificateConfiguration, Error> {
            unimplemented!("noop backend cannot load certificates")
        }

        fn load_certificate_private_key(&self, _id: &str) -> Result<KeyPair, Error> {
            unimplemented!("noop backend cannot load private keys")
        }

        fn load_certificate_files(
            &self,
            _id: &str,
            _limit: Option<usize>,
        ) -> Result<Vec<ParsedX509Certificate>, Error> {
            unimplemented!("noop backend cannot load certificate files")
        }

        fn save_certificate_config(
            &self,
            _id: &str,
            _config: &CertificateConfiguration,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn save_certificate_private_key(&self, _id: &str, _key: &KeyPair) -> Result<(), Error> {
            Ok(())
        }

        fn save_certificate_file(
            &self,
            _id: &str,
            _cert: &DownloadedCertificate,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn list_certificates(&self) -> Result<Vec<String>, Error> {
            Ok(Vec::new())
        }

        fn certificate_directory(&self, _id: &str) -> PathBuf {
            PathBuf::from("/dev/null")
        }
    }
}
