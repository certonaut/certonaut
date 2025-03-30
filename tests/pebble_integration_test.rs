use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::config::test_backend::{NoopBackend, new_configuration_manager_with_noop_backend};
use certonaut::config::{AccountConfiguration, CertificateAuthorityConfiguration};
use certonaut::crypto::asymmetric::KeyPair;
use certonaut::dns::resolver::Resolver;
use certonaut::pebble::{
    ChallengeTestDnsSolver, ChallengeTestHttpSolver, PEBBLE_CHALLTESTSRV_BASE_URL, pebble_root,
};
use certonaut::{AcmeAccount, Authorizer, Certonaut, Identifier};
use serde::Serialize;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::net::UdpSocket;
use url::Url;

const PEBBLE_URL: &str = "https://localhost:14000/dir";
const CA_NAME: &str = "pebble";
const ACCOUNT_NAME: &str = "pebble-account";

async fn setup_pebble_issuer() -> anyhow::Result<Certonaut<NoopBackend>> {
    tracing_subscriber::fmt::try_init().ok();
    let acme_url = Url::parse(PEBBLE_URL)?;
    let http_client = HttpClient::try_new_with_custom_root(pebble_root()?)?;
    let acme_client = AcmeClientBuilder::new(acme_url.clone())
        .with_http_client(http_client)
        .try_build()
        .await?;
    let key_file = Path::new("testdata/account.key");
    let keypair = KeyPair::load_from_disk(File::open(key_file)?)?;
    let register_options = AccountRegisterOptions {
        key: keypair,
        contact: vec!["mailto:admin@example.org".parse()?],
        terms_of_service_agreed: Some(true),
    };
    let (jwk, account_url, _account) = acme_client.register_account(register_options).await?;
    let test_db = certonaut::state::open_test_db().await;
    let resolver = Resolver::new();
    let mut certonaut = Certonaut::try_new(
        new_configuration_manager_with_noop_backend(),
        test_db.into(),
        resolver,
    )?;
    certonaut.add_new_ca(CertificateAuthorityConfiguration {
        name: CA_NAME.to_string(),
        identifier: CA_NAME.to_string(),
        acme_directory: acme_url,
        public: false,
        testing: true,
        default: false,
    })?;
    certonaut.add_new_account(
        CA_NAME,
        AcmeAccount::new_account(
            AccountConfiguration {
                name: ACCOUNT_NAME.to_string(),
                identifier: ACCOUNT_NAME.to_string(),
                key_file: PathBuf::new(),
                url: account_url,
            },
            jwk,
        ),
    )?;
    Ok(certonaut)
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test_http() -> anyhow::Result<()> {
    let certonaut = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str("pebble-e2e-http01.example.com")?,
        ChallengeTestHttpSolver::default(),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test_dns() -> anyhow::Result<()> {
    let certonaut = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str("pebble-e2e-dns01.example.com")?,
        ChallengeTestDnsSolver::default(),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test_wildcard() -> anyhow::Result<()> {
    let certonaut = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str("*.pebble-e2e-wildcard-single.example.com")?,
        ChallengeTestDnsSolver::default(),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test_multi_domain_with_wildcard() -> anyhow::Result<()> {
    let certonaut = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![
        Authorizer::new(
            Identifier::from_str("*.pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestDnsSolver::default(),
        ),
        Authorizer::new(
            Identifier::from_str("pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestHttpSolver::default(),
        ),
        Authorizer::new(
            Identifier::from_str("pebble-e2e-multi.example.com")?,
            ChallengeTestHttpSolver::default(),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test_idna_names() -> anyhow::Result<()> {
    let certonaut = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![
        Authorizer::new(
            Identifier::from_str("*.Bücher.example")?,
            ChallengeTestDnsSolver::default(),
        ),
        Authorizer::new(
            Identifier::from_str("Bücher.example")?,
            ChallengeTestHttpSolver::default(),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
/// - The test must be run with at least CAP_BPF and CAP_NET_ADMIN privileges
async fn magic_solver_e2e_test() -> anyhow::Result<()> {
    let test_host = "magic-solver-e2e-test.example.org";
    let helper = MagicPebbleHelper::new(test_host.to_string());
    helper
        .run(async move || {
            let certonaut = setup_pebble_issuer().await?;
            let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
            let new_key = rcgen::KeyPair::generate()?;
            let authorizers = vec![Authorizer::new(
                Identifier::from_str(test_host)?,
                certonaut::magic::MagicHttpSolver::new(5002),
            )];

            let _cert = issuer
                .issue(&new_key, None, authorizers, None, None)
                .await?;

            Ok::<(), anyhow::Error>(())
        })
        .await?
}

#[allow(dead_code)]
struct MagicPebbleHelper {
    client: reqwest::Client,
    host: String,
}

#[allow(dead_code)]
impl MagicPebbleHelper {
    /// Find this host's IP address on any external interface
    async fn get_host_ip() -> std::io::Result<IpAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        // Doesn't actually send any packets, just for routing purposes
        socket.connect("8.8.8.8:80").await?;
        socket.local_addr().map(|addr| addr.ip())
    }

    #[must_use]
    pub fn new(host: String) -> Self {
        let client = reqwest::Client::new();
        Self { client, host }
    }

    async fn setup_non_localhost_dns(&self) -> anyhow::Result<()> {
        let host_ip = Self::get_host_ip().await?;
        let response = self
            .client
            .post(PEBBLE_CHALLTESTSRV_BASE_URL.join("add-a")?)
            .json(&MockHostIpAddr {
                host: &self.host,
                addresses: vec![host_ip],
            })
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }

    async fn cleanup(self) -> anyhow::Result<()> {
        let response = self
            .client
            .post(PEBBLE_CHALLTESTSRV_BASE_URL.join("clear-a")?)
            .json(&MockHostIpAddr {
                host: &self.host,
                addresses: vec![],
            })
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }

    pub async fn run<O, F: AsyncFn() -> O>(self, f: F) -> anyhow::Result<O> {
        self.setup_non_localhost_dns().await?;
        let output = f().await;
        self.cleanup().await?;
        Ok(output)
    }
}

#[allow(dead_code)]
#[derive(Serialize)]
struct MockHostIpAddr<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<IpAddr>,
}
