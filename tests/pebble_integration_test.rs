mod common;

use crate::common::{ChallengeTestServerContainer, PebbleContainer};
use certonaut::config::PebbleHttpSolverConfiguration;
use certonaut::config::test_backend::{NoopBackend, new_configuration_manager_with_noop_backend};
use certonaut::crypto::asymmetric;
use certonaut::crypto::asymmetric::{Curve, KeyType};
use certonaut::dns::resolver::Resolver;
use certonaut::pebble::{ChallengeTestDnsSolver, ChallengeTestHttpSolver};
use certonaut::{Authorizer, Certonaut, Identifier};
use hickory_resolver::config::NameServerConfigGroup;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Weak};
use test_log::test;
use tokio::sync::Mutex;

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
        println!("host IP: {host_ip}");
        let challtest = ChallengeTestServerContainer::spawn(5002, 8053, host_ip).await?;
        let dns_server = challtest.get_dns_url();
        let pebble = PebbleContainer::spawn(dns_server).await?;
        let new_containers = Arc::new((pebble, challtest));
        *fixture = Arc::downgrade(&new_containers);
        Ok(new_containers)
    }
}

async fn test_setup() -> anyhow::Result<(TestContainersHandle, Certonaut<NoopBackend>)> {
    let containers = setup_pebble_containers_once().await?;
    let test_db = certonaut::state::open_test_db().await;
    let resolver = Resolver::new_with_upstream(NameServerConfigGroup::from_ips_clear(
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        containers.1.dns_port,
        true,
    ));
    let certonaut = Certonaut::try_new(
        new_configuration_manager_with_noop_backend(),
        test_db.into(),
        resolver,
    )?;
    let certonaut =
        common::setup_pebble_issuer(PebbleContainer::get_directory_url(), certonaut).await?;
    Ok((containers, certonaut))
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_http() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("pebble-e2e-http01.example.com")?,
        ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
            base_url: containers.1.get_management_url(),
        }),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_dns() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("pebble-e2e-dns01.example.com")?,
        ChallengeTestDnsSolver::new(containers.1.get_management_url()),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_wildcard() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("*.pebble-e2e-wildcard-single.example.com")?,
        ChallengeTestDnsSolver::new(containers.1.get_management_url()),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_multi_domain_with_wildcard() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![
        Authorizer::new_boxed(
            Identifier::from_str("*.pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("pebble-e2e-wildcard-multi.example.com")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url(),
            }),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("pebble-e2e-multi.example.com")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url(),
            }),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_idna_names() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![
        Authorizer::new_boxed(
            Identifier::from_str("*.Bücher.example")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("Bücher.example")?,
            ChallengeTestDnsSolver::new(containers.1.get_management_url()),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn pebble_e2e_test_ip_addr() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let authorizers = vec![
        Authorizer::new_boxed(
            Identifier::from_str("192.0.2.1")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url(),
            }),
        ),
        Authorizer::new_boxed(
            Identifier::from_str("2001:db8::3")?,
            ChallengeTestHttpSolver::from_config(PebbleHttpSolverConfiguration {
                base_url: containers.1.get_management_url(),
            }),
        ),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
#[test(tokio::test)]
#[ignore = "integration-test; requires prerequisites"]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
/// - The test must be run with at least CAP_BPF and CAP_NET_ADMIN privileges
async fn magic_solver_e2e_test() -> anyhow::Result<()> {
    let test_host = "magic-solver-e2e-test.example.org";
    let (_containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let http_port = 5002;
    println!("Validation port is {http_port}");
    let authorizers = vec![Authorizer::new(
        Identifier::from_str(test_host)?,
        certonaut::magic::MagicHttpSolver::new(http_port),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}
