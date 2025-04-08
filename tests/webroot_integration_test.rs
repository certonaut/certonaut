use crate::common::{
    ACCOUNT_NAME, CA_NAME, ChallengeTestServerContainer, PebbleContainer, TestLogConsumer,
};
use anyhow::Context;
use certonaut::challenge_solver::WebrootSolver;
use certonaut::config::WebrootSolverConfiguration;
use certonaut::config::test_backend::{NoopBackend, new_configuration_manager_with_noop_backend};
use certonaut::dns::resolver::Resolver;
use certonaut::{Authorizer, Certonaut, Identifier};
use hickory_resolver::config::NameServerConfigGroup;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Weak};
use tempfile::{TempDir, tempdir};
use testcontainers::core::{IntoContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::Mutex;
use tracing::debug;

mod common;

type TestContainers = (
    PebbleContainer,
    ChallengeTestServerContainer,
    WebServerContainer,
);
type TestContainersHandle = Arc<TestContainers>;

struct WebServerContainer {
    // Drop order matters: Stop the container before removing the tempdir
    _inner: ContainerAsync<GenericImage>,
    webroot: TempDir,
}

impl WebServerContainer {
    pub async fn spawn(challenge_port: u16) -> anyhow::Result<Self> {
        let webroot = tempdir()?;
        let webroot_path = webroot
            .path()
            .to_str()
            .context("temp dir path must be valid UTF-8")?;
        let challenge_port = challenge_port.tcp();
        let spawned_container =
            GenericImage::new("ghcr.io/static-web-server/static-web-server", "latest")
                .with_env_var("SERVER_PORT", challenge_port.as_u16().to_string())
                .with_mapped_port(challenge_port.as_u16(), challenge_port)
                .with_mount(Mount::bind_mount(webroot_path, "/public"))
                .with_log_consumer(TestLogConsumer::default())
                .start()
                .await
                .context("Failed to start static web server")?;
        Ok(Self {
            _inner: spawned_container,
            webroot,
        })
    }
}

/// Spawn the testcontainers (pebble + challtest + static web server), if not already done
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
        debug!("host IP: {host_ip}");
        let challtest = common::spawn_challtestsrv_container(host_ip, 0, 8053).await?;
        let dns_server = challtest.get_dns_url(host_ip)?;
        let pebble = common::spawn_pebble_container(dns_server).await?;
        let webserver = WebServerContainer::spawn(5002).await?;
        let new_containers = Arc::new((pebble, challtest, webserver));
        *fixture = Arc::downgrade(&new_containers);
        Ok(new_containers)
    }
}

async fn test_setup() -> anyhow::Result<(TestContainersHandle, Certonaut<NoopBackend>)> {
    tracing_subscriber::fmt::try_init().ok();
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
        common::setup_pebble_issuer(containers.0.get_directory_url()?, certonaut).await?;
    Ok((containers, certonaut))
}

#[tokio::test]
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn webroot_solver_e2e_test() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = rcgen::KeyPair::generate()?;
    let authorizers = vec![Authorizer::new_boxed(
        Identifier::from_str("webroot-e2e-test.example.org")?,
        WebrootSolver::from_config(WebrootSolverConfiguration {
            webroot: containers.2.webroot.path().to_path_buf(),
        }),
    )];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}
