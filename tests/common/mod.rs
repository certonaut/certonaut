#![allow(dead_code)]

use anyhow::Context;
use bstr::ByteSlice;
use certonaut::acme::client::{AccountRegisterOptions, AcmeClientBuilder};
use certonaut::acme::http::HttpClient;
use certonaut::config::{AccountConfiguration, CertificateAuthorityConfiguration, ConfigBackend};
use certonaut::crypto::asymmetric::KeyPair;
use certonaut::{AcmeAccount, Certonaut};
use futures::FutureExt;
use futures::future::BoxFuture;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use testcontainers::core::WaitFor;
use testcontainers::core::logs::LogFrame;
use testcontainers::core::logs::consumer::LogConsumer;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::UdpSocket;
use url::Url;

pub mod dns;

pub const CA_NAME: &str = "pebble";
pub const ACCOUNT_NAME: &str = "pebble-account";
pub const HOST_NETWORK: &str = "host";

#[derive(Debug)]
pub struct PebbleContainer {
    _inner: ContainerAsync<GenericImage>,
}

impl PebbleContainer {
    pub async fn spawn(dns_server: Url) -> anyhow::Result<Self> {
        let dns_server = dns_server.authority();
        let spawned_container = GenericImage::new("ghcr.io/letsencrypt/pebble", "latest")
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
            .with_network(HOST_NETWORK)
            .with_log_consumer(TestLogConsumer::default())
            .start()
            .await
            .context("Failed to start pebble")?;
        Ok(Self {
            _inner: spawned_container,
        })
    }

    pub fn get_directory_url() -> Url {
        Url::parse("https://localhost:14000/dir").unwrap()
    }

    pub fn get_management_url() -> Url {
        Url::parse("http://localhost:15000").unwrap()
    }
}

#[derive(Debug)]
pub struct ChallengeTestServerContainer {
    pub dns_port: u16,
    _inner: ContainerAsync<GenericImage>,
}

impl ChallengeTestServerContainer {
    pub async fn spawn(
        validation_port: u16,
        dns_port: u16,
        host_ip: IpAddr,
    ) -> anyhow::Result<ChallengeTestServerContainer> {
        // Ensure challtestsrv resolves to the host by default
        let (default_ipv4, default_ipv6) = match host_ip {
            IpAddr::V4(host_ip) => (host_ip.to_string(), String::new()),
            IpAddr::V6(host_ip) => (String::new(), host_ip.to_string()),
        };
        let spawned_container =
            GenericImage::new("ghcr.io/letsencrypt/pebble-challtestsrv", "latest")
                .with_wait_for(WaitFor::message_on_stdout("Starting challenge servers"))
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
                .with_network(HOST_NETWORK)
                .with_log_consumer(TestLogConsumer::default())
                .start()
                .await
                .context("Failed to start challtestsrv")?;
        Ok(Self {
            dns_port,
            _inner: spawned_container,
        })
    }

    #[allow(clippy::unused_self)]
    pub fn get_management_url(&self) -> Url {
        Url::parse("http://localhost:8055").unwrap()
    }

    pub fn get_dns_url(&self) -> Url {
        Url::parse(&format!("dns://localhost:{}", self.dns_port)).unwrap()
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

async fn setup_http_client() -> anyhow::Result<HttpClient> {
    let certs = certonaut::cert::load_reqwest_certificates(
        [Path::new("testdata/certs/pebble.minica.pem")].iter(),
    )
    .await?;
    Ok(HttpClient::try_new_with_custom_roots(certs)?)
}

pub async fn setup_pebble_issuer<T: ConfigBackend>(
    acme_url: Url,
    mut certonaut: Certonaut<T>,
) -> anyhow::Result<Certonaut<T>> {
    let http_client = setup_http_client().await?;
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
        trusted_roots: vec![PathBuf::from("testdata/certs/pebble.minica.pem")],
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
