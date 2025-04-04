mod common;

use crate::common::{ChallengeTestServerContainer, PebbleContainer};
use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::config::test_backend::{new_configuration_manager_with_noop_backend, NoopBackend};
use certonaut::config::{
    AccountConfiguration, CertificateAuthorityConfiguration, PebbleHttpSolverConfiguration,
};
use certonaut::crypto::asymmetric::KeyPair;
use certonaut::dns::resolver::Resolver;
use certonaut::pebble::{pebble_root, ChallengeTestDnsSolver, ChallengeTestHttpSolver};
use certonaut::{AcmeAccount, Authorizer, Certonaut, Identifier};
use hickory_resolver::config::NameServerConfigGroup;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use url::Url;

const CA_NAME: &str = "pebble";
const ACCOUNT_NAME: &str = "pebble-account";

type TestContainers = (PebbleContainer, ChallengeTestServerContainer);
type TestContainersHandle = Arc<TestContainers>;

/// Spawn the testcontainers (pebble + challtestsrv), if not already done
///
/// # Returns
///
/// A handle to the spawned testcontainers. The containers will be stopped after the last handle is dropped.
async fn setup_pebble_containers_once() -> anyhow::Result<TestContainersHandle> {
    static FIXTURE: Mutex<Weak<TestContainers>> = Mutex::const_new(Weak::new());
    let mut fixture = FIXTURE.lock().await;
    if let Some(existing_containers) = fixture.upgrade() {
        Ok(existing_containers)
    } else {
        let host_ip = common::get_host_ip().await?;
        let challtest = common::spawn_challtestsrv_container(host_ip).await?;
        let dns_server = Url::parse(&format!(
            "dns://host.docker.internal:{}",
            challtest.dns_port
        ))?;
        let pebble = common::spawn_pebble_container(dns_server).await?;
        let new_containers = Arc::new((pebble, challtest));
        *fixture = Arc::downgrade(&new_containers);
        Ok(new_containers)
    }
}

async fn setup_pebble_issuer() -> anyhow::Result<(TestContainersHandle, Certonaut<NoopBackend>)> {
    tracing_subscriber::fmt::try_init().ok();
    let containers = setup_pebble_containers_once().await?;
    let acme_url = containers.0.get_directory_url()?;
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
    let resolver = Resolver::new_with_upstream(NameServerConfigGroup::from_ips_clear(
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        containers.1.dns_port,
        true,
    ));
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
    Ok((containers, certonaut))
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_http() -> anyhow::Result<()> {
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("pebble-e2e-http01.example.com")?,
        ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
            base_url: containers.1.get_management_url()?,
        }),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_dns() -> anyhow::Result<()> {
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("pebble-e2e-dns01.example.com")?,
        ChallengeTestDnsSolver::new(containers.1.get_management_url()?),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_wildcard() -> anyhow::Result<()> {
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("*.pebble-e2e-wildcard-single.example.com")?,
        ChallengeTestDnsSolver::new(containers.1.get_management_url()?),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_multi_domain_with_wildcard() -> anyhow::Result<()> {
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![
        Authorizer::new_boxed(
            Identifier::from_str("*.pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()?),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url()?,
            }),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("pebble-e2e-multi.example.com")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url()?,
            }),
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
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_idna_names() -> anyhow::Result<()> {
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![
        Authorizer::new_boxed(
            Identifier::from_str("*.Bücher.example")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()?),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("Bücher.example")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()?),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

// #[tokio::test]
// #[ignore]
// WIP
// async fn webroot_solver_e2e_test() -> anyhow::Result<()> {
//     let certonaut = setup_pebble_issuer().await?;
//     let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
//     let new_key = rcgen::KeyPair::generate()?;
//     let test_client = pebble::ChallengeTestServerClient::default();
//     // test_client.add_http_redirect()
//     let authorizers = vec![Authorizer::new_boxed(
//         Identifier::from_str("webroot-e2e-test.example.org")?,
//         WebrootSolver::from_config(WebrootSolverConfiguration {
//             webroot: "/var/www/html".into(),
//         }),
//     )];
//
//     let _cert = issuer
//         .issue(&new_key, None, authorizers, None, None)
//         .await?;
//
//     Ok(())
// }

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
/// - The test must be run with at least CAP_BPF and CAP_NET_ADMIN privileges
async fn magic_solver_e2e_test() -> anyhow::Result<()> {
    let test_host = "magic-solver-e2e-test.example.org";
    let (containers, certonaut) = setup_pebble_issuer().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new(
        Identifier::from_str(test_host)?,
        certonaut::magic::MagicHttpSolver::new(containers.1.http_port),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}
