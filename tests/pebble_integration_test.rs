use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::acme::object::Identifier;
use certonaut::config::{AccountConfiguration, CertificateAuthorityConfiguration, Configuration, MainConfiguration};
use certonaut::crypto::asymmetric;
use certonaut::crypto::asymmetric::{Curve, KeyPair, KeyType};
use certonaut::pebble::{pebble_root, ChallengeTestHttpSolver};
use certonaut::{AcmeAccount, Authorizer, Certonaut};
use std::fs::File;
use std::path::{Path, PathBuf};
use url::Url;

const PEBBLE_URL: &str = "https://localhost:14000/dir";

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, and be configured to use challtestsrv
/// - Pebble-challtestsrv must be running on its default port
async fn pebble_e2e_test() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
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
    let mut certonaut = Certonaut::try_new(Configuration {
        main: MainConfiguration { ca_list: vec![] },
        #[allow(clippy::default_trait_access)]
        certificates: Default::default(),
    })?;
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
        Identifier::from("example.com".to_string()),
        ChallengeTestHttpSolver::default(),
    )];
    issuer
        .issue(
            &asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?,
            None,
            authorizers,
        )
        .await?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - Pebble must be running on its default port, with the pebble-default HTTP-01 port (5002)
/// - Pebble must **not** connect to the webserver over 127.0.0.1, i.e. the default IPv4 address must be set to an
/// external IP address.
/// - The test must be run with at least CAP_BPF and CAP_NET_ADMIN privileges
async fn magic_solver_e2e_test() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let acme_url = Url::parse(PEBBLE_URL)?;
    let http_client = HttpClient::try_new_with_custom_root(pebble_root()?)?;
    let acme_client = AcmeClientBuilder::new(acme_url)
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
    let mut issuer = AcmeIssuer::new(
        Arc::new(acme_client),
        AcmeAccount::new_account(
            AccountConfiguration {
                name: "pebble-e2e-test".to_string(),
                identifier: "pebble-e2e-test".to_string(),
                key_file: key_file.to_path_buf(),
                url: account_url,
            },
            jwk,
        ),
    );

    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str("example.com")?,
        MagicHttpSolver::new(5002),
    )];
    let _cert = issuer.issue(&new_key, None, authorizers).await?;
    Ok(())
}
