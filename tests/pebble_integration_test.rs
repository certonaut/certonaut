use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::config::test_backend::new_configuration_manager_with_noop_backend;
use certonaut::config::{AccountConfiguration, CertificateAuthorityConfiguration, Identifier};
use certonaut::crypto::asymmetric;
use certonaut::crypto::asymmetric::{Curve, KeyPair, KeyType};
use certonaut::pebble::{ChallengeTestHttpSolver, PEBBLE_CHALLTESTSRV_BASE_URL, pebble_root};
use certonaut::{AcmeAccount, Authorizer, Certonaut};
use serde::Serialize;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::net::UdpSocket;
use url::Url;

const PEBBLE_URL: &str = "https://localhost:14000/dir";

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test() -> anyhow::Result<()> {
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
    // TODO: Refactor for better test usage
    // Configuration {
    //     main: MainConfiguration { ca_list: vec![] },
    //     #[allow(clippy::default_trait_access)]
    //     certificates: Default::default(),
    // }
    let test_db = certonaut::state::open_test_db().await;
    let mut certonaut = Certonaut::try_new(
        new_configuration_manager_with_noop_backend(),
        test_db.into(),
    )?;
    certonaut.add_new_ca(CertificateAuthorityConfiguration {
        name: "pebble".to_string(),
        identifier: "pebble".to_string(),
        acme_directory: acme_url,
        public: false,
        testing: true,
        default: false,
    })?;
    certonaut.add_new_account(
        "pebble",
        AcmeAccount::new_account(
            AccountConfiguration {
                name: "pebble-account".to_string(),
                identifier: "pebble-account".to_string(),
                key_file: PathBuf::new(),
                url: account_url,
            },
            jwk,
        ),
    )?;
    let issuer = certonaut.get_issuer_with_account("pebble", "pebble-account")?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str("pebble-e2e.example.com")?,
        ChallengeTestHttpSolver::default(),
    )];
    issuer
        .issue(
            &asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?,
            None,
            authorizers,
            None,
        )
        .await?;
    Ok(())
}

#[allow(dead_code)]
async fn get_host_ip() -> IpAddr {
    // Quick hack to find the host's IP
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    // Doesn't actually send any packets, just for routing purposes
    socket.connect("8.8.8.8:80").await.unwrap();
    socket.local_addr().ok().map(|addr| addr.ip()).unwrap()
}

#[allow(dead_code)]
#[derive(Serialize)]
struct MockHostIpAddr {
    host: String,
    addresses: Vec<IpAddr>,
}

#[allow(dead_code)]
async fn setup_non_localhost_dns(host: String) -> anyhow::Result<()> {
    let host_ip = get_host_ip().await;
    let client = reqwest::Client::new();
    client
        .post(PEBBLE_CHALLTESTSRV_BASE_URL.join("add-a").unwrap())
        .json(&MockHostIpAddr {
            host,
            addresses: vec![host_ip],
        })
        .send()
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
    tracing_subscriber::fmt::try_init().ok();
    let test_host = "magic-solver-e2e-test.example.org".to_string();
    setup_non_localhost_dns(test_host.clone()).await?;
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
    let mut certonaut = Certonaut::try_new(
        new_configuration_manager_with_noop_backend(),
        test_db.into(),
    )?;
    certonaut.add_new_ca(CertificateAuthorityConfiguration {
        name: "pebble".to_string(),
        identifier: "pebble".to_string(),
        acme_directory: acme_url,
        public: false,
        testing: true,
        default: false,
    })?;
    certonaut.add_new_account(
        "pebble",
        AcmeAccount::new_account(
            AccountConfiguration {
                name: "pebble-account".to_string(),
                identifier: "pebble-account".to_string(),
                key_file: PathBuf::new(),
                url: account_url,
            },
            jwk,
        ),
    )?;
    let issuer = certonaut.get_issuer_with_account("pebble", "pebble-account")?;

    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from(test_host),
        certonaut::magic::MagicHttpSolver::new(5002),
    )];
    let _cert = issuer.issue(&new_key, None, authorizers, None).await?;
    Ok(())
}
