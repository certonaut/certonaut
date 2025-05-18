use crate::common::dns::StubDnsResolver;
use crate::common::{ACCOUNT_NAME, CA_NAME, HOST_NETWORK, PebbleContainer, TestLogConsumer};
use anyhow::{Context, bail};
use certonaut::config::test_backend::{NoopBackend, new_configuration_manager_with_noop_backend};
use certonaut::crypto::asymmetric;
use certonaut::crypto::asymmetric::{Curve, KeyType};
use certonaut::dns::name::DnsName;
use certonaut::dns::resolver::Resolver;
use certonaut::dns::solver::acme_dns;
use certonaut::dns::solver::acme_dns::Registration;
use certonaut::{Authorizer, Certonaut, Identifier};
use hickory_resolver::config::NameServerConfigGroup;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::{TempDir, tempdir};
use test_log::test;
use testcontainers::core::{Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use url::Url;

mod common;

type TestSetup = (PebbleContainer, StubDnsResolver);

struct AcmeDnsContainer {
    // Drop order matters: Stop container before cleaning up files
    _inner: ContainerAsync<GenericImage>,
    _data_dir: TempDir,
}

impl AcmeDnsContainer {
    async fn create_acme_dns_config(base_dir: &Path) -> anyhow::Result<PathBuf> {
        let config_file_path = base_dir.join("config.cfg");
        let mut config_file = File::create_new(&config_file_path).await?;
        let config = include_str!("../testdata/configs/acme_dns.toml");
        config_file.write_all(config.as_bytes()).await?;
        Ok(config_file_path)
    }

    pub async fn spawn() -> anyhow::Result<Self> {
        let data_dir = tempdir()?;
        let config_file = Self::create_acme_dns_config(data_dir.path()).await?;
        let spawned_container = GenericImage::new("ghcr.io/certonaut/acme-dns-ci", "latest")
            .with_wait_for(WaitFor::message_on_stderr("Listening DNS"))
            .with_mount(Mount::bind_mount(
                config_file
                    .to_str()
                    .context("Config file path must be valid UTF-8")?,
                "/etc/acme-dns/config.cfg",
            ))
            .with_mount(Mount::bind_mount(
                data_dir
                    .path()
                    .to_str()
                    .context("Data directory must be valid UTF-8")?,
                "/var/lib/acme-dns",
            ))
            .with_network(HOST_NETWORK)
            .with_log_consumer(TestLogConsumer::default())
            .start()
            .await
            .context("Failed to start static web server")?;
        Ok(Self {
            _inner: spawned_container,
            _data_dir: data_dir,
        })
    }

    #[allow(clippy::unused_self)]
    pub fn get_api_url(&self) -> Url {
        Url::parse("http://localhost:5003").unwrap()
    }
}

/// Spawn the testcontainers (pebble + stub dns resolver) with the given upstream DNS server
///
///
/// # Returns
///
/// The testcontainer instance of Pebble and a local stub DNS server that can be stubbed to provide custom DNS responses
/// for the `local.test` zone
async fn setup_pebble_and_dns(upstream_dns: NameServerConfigGroup) -> anyhow::Result<TestSetup> {
    let stub_dns = StubDnsResolver::try_new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8053),
        DnsName::try_from("local.test")?.into(),
        upstream_dns,
    )
    .await?;
    let dns_server = stub_dns.get_dns_url()?;
    let pebble = PebbleContainer::spawn(dns_server).await?;
    let containers = (pebble, stub_dns);
    Ok(containers)
}

async fn test_setup(
    upstream_dns: NameServerConfigGroup,
) -> anyhow::Result<(TestSetup, Certonaut<NoopBackend>)> {
    let containers = setup_pebble_and_dns(upstream_dns).await?;
    let test_db = certonaut::state::open_test_db().await;
    let resolver = Resolver::new_with_upstream(NameServerConfigGroup::from_ips_clear(
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        containers.1.listen_port(),
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
#[ignore]
/// Note that this test requires prerequisites to be setup beforehand
/// - The test needs access to a Docker engine running locally
async fn acme_dns_solver_e2e_test() -> anyhow::Result<()> {
    let (containers, certonaut) = test_setup(NameServerConfigGroup::from_ips_clear(
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        8054,
        true,
    ))
    .await?;
    let acme_dns = AcmeDnsContainer::spawn().await?;
    let issuer = certonaut.get_issuer_with_account(CA_NAME, ACCOUNT_NAME)?;
    let new_key = asymmetric::new_key(KeyType::Ecdsa(Curve::P256))?;
    let acme_dns_client = acme_dns::Client::new(acme_dns.get_api_url(), reqwest::Client::new());
    let registration: Registration = acme_dns_client.register(std::iter::empty()).await?.into();
    let domain_name = Identifier::from_str("acme-dns-e2e-test.local.test")?;
    let domain_name_wildcard = Identifier::from_str("*.acme-dns-e2e-test.local.test")?;
    let acme_challenge_name = match &domain_name {
        Identifier::Dns(dns_name) => dns_name.to_acme_challenge_name()?,
        _ => bail!("Test identifier must be of DNS type"),
    };
    let cname_target = DnsName::try_from(registration.full_domain.clone())?;
    containers
        .1
        .authority()
        .add_cname(acme_challenge_name, cname_target)
        .await?;
    let solver = acme_dns::Solver::new(acme_dns_client.clone(), registration.clone());
    let solver_wildcard = acme_dns::Solver::new(acme_dns_client, registration);
    let authorizers = vec![
        Authorizer::new(domain_name_wildcard, solver_wildcard),
        Authorizer::new(domain_name, solver),
    ];

    let _cert = issuer
        .issue(&new_key, None, authorizers, None, None)
        .await?;

    Ok(())
}
