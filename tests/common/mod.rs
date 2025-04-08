#![allow(dead_code)]

use anyhow::Context;
use bstr::ByteSlice;
use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::config::{AccountConfiguration, CertificateAuthorityConfiguration, ConfigBackend};
use certonaut::crypto::asymmetric::KeyPair;
use certonaut::pebble::pebble_root;
use certonaut::{AcmeAccount, Certonaut};
use futures::FutureExt;
use futures::future::BoxFuture;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use testcontainers::core::logs::LogFrame;
use testcontainers::core::logs::consumer::LogConsumer;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::UdpSocket;
use url::Url;

pub mod dns;

pub const CA_NAME: &str = "pebble";
pub const ACCOUNT_NAME: &str = "pebble-account";

/// Run pebble in a Docker testcontainer
pub async fn spawn_pebble_container(dns_server: Url) -> anyhow::Result<PebbleContainer> {
    let api_port = 14000.tcp();
    let management_port = 15000.tcp();
    let dns_server = dns_server.authority();
    let spawned_container = GenericImage::new("ghcr.io/letsencrypt/pebble", "latest")
        .with_exposed_port(api_port)
        .with_exposed_port(management_port)
        .with_wait_for(WaitFor::message_on_stdout(
            "ACME directory available at: https://0.0.0.0:14000/dir",
        ))
        .with_cmd([
            "-config",
            "test/config/pebble-config.json",
            "-strict",
            "-dnsserver",
            dns_server,
        ])
        .with_log_consumer(TestLogConsumer::default())
        .start()
        .await
        .context("Failed to start pebble")?;
    let port_mapping = spawned_container
        .ports()
        .await
        .context("Failed to retrieve port mapping for pebble")?;
    let api_port = port_mapping
        .map_to_host_port_ipv4(api_port)
        .context("Failed to retrieve API port (pebble)")?;
    let management_port = port_mapping
        .map_to_host_port_ipv4(management_port)
        .context("Failed to retrieve management port (pebble)")?;
    Ok(PebbleContainer::new(
        api_port,
        management_port,
        spawned_container,
    ))
}

/// Run pebble's challtestsrv in a Docker testcontainer
pub async fn spawn_challtestsrv_container(
    host_ip: IpAddr,
    validation_port: u16,
    dns_port: u16,
) -> anyhow::Result<ChallengeTestServerContainer> {
    let management_port = 8055.tcp();
    let http_port = validation_port.tcp();
    let dns_port_udp = dns_port.udp();
    let dns_port_tcp = dns_port.tcp();
    // Ensure challtestsrv resolves to the host by default
    let (default_ipv4, default_ipv6) = match host_ip {
        IpAddr::V4(v4) => (v4.to_string(), String::new()),
        IpAddr::V6(v6) => (String::new(), v6.to_string()),
    };
    let spawned_container = GenericImage::new("ghcr.io/letsencrypt/pebble-challtestsrv", "latest")
        .with_wait_for(WaitFor::message_on_stdout("Starting challenge servers"))
        // map these ports statically - this unfortunately can cause port clashes (simultaneous test runs, other apps),
        // but it's the easiest way to ensure that pebble can reach the challtestsrv on the proper validation port
        .with_mapped_port(http_port.as_u16(), http_port)
        .with_mapped_port(management_port.as_u16(), management_port)
        .with_mapped_port(dns_port_udp.as_u16(), dns_port_udp)
        .with_mapped_port(dns_port_tcp.as_u16(), dns_port_tcp)
        .with_cmd([
            "-defaultIPv4",
            &default_ipv4,
            "-defaultIPv6",
            &default_ipv6,
            "-dns01",
            &format!(":{dns_port}"),
            "-http01",
            &format!(":{validation_port}"),
        ])
        .with_log_consumer(TestLogConsumer::default())
        .start()
        .await
        .context("Failed to start challtestsrv")?;
    Ok(ChallengeTestServerContainer::new(
        management_port.as_u16(),
        http_port.as_u16(),
        dns_port,
        spawned_container,
    ))
}

pub struct PebbleContainer {
    api_port: u16,
    management_port: u16,
    _inner: ContainerAsync<GenericImage>,
}

impl PebbleContainer {
    fn new(api_port: u16, management_port: u16, container: ContainerAsync<GenericImage>) -> Self {
        Self {
            api_port,
            management_port,
            _inner: container,
        }
    }

    pub fn get_directory_url(&self) -> Result<Url, url::ParseError> {
        Url::parse(&format!("https://localhost:{}/dir", self.api_port))
    }

    pub fn get_management_url(&self) -> Result<Url, url::ParseError> {
        Url::parse(&format!("http://localhost:{}", self.management_port))
    }
}

pub struct ChallengeTestServerContainer {
    management_port: u16,
    pub http_port: u16,
    pub dns_port: u16,
    _inner: ContainerAsync<GenericImage>,
}

impl ChallengeTestServerContainer {
    fn new(
        management_port: u16,
        http_port: u16,
        dns_port: u16,
        container: ContainerAsync<GenericImage>,
    ) -> Self {
        Self {
            management_port,
            http_port,
            dns_port,
            _inner: container,
        }
    }

    pub fn get_management_url(&self) -> Result<Url, url::ParseError> {
        Url::parse(&format!("http://localhost:{}", self.management_port))
    }

    pub fn get_dns_url(&self, host_ip: IpAddr) -> Result<Url, url::ParseError> {
        Url::parse(&format!("dns://{host_ip}:{}", self.dns_port))
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestLogConsumer {}

impl LogConsumer for TestLogConsumer {
    fn accept<'a>(&'a self, record: &'a LogFrame) -> BoxFuture<'a, ()> {
        match record {
            LogFrame::StdOut(data) => print!("{}", data.to_str_lossy()),
            LogFrame::StdErr(data) => eprint!("{}", data.to_str_lossy()),
        }
        futures::future::ready(()).boxed()
    }
}

/// Find this host's IP address on any external interface
pub async fn get_host_ip() -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // Doesn't actually send any packets, just for routing purposes
    socket.connect("8.8.8.8:80").await?;
    socket.local_addr().map(|addr| addr.ip())
}

pub async fn setup_pebble_issuer<T: ConfigBackend>(
    acme_url: Url,
    mut certonaut: Certonaut<T>,
) -> anyhow::Result<Certonaut<T>> {
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
