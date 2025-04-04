use anyhow::Context;
use std::net::IpAddr;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::UdpSocket;
use url::Url;

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
) -> anyhow::Result<ChallengeTestServerContainer> {
    let management_port = 8055.tcp();
    let http_port = 5002.tcp();
    let dns_port = 8053.udp();
    // Ensure challtestsrv resolves to the host by default
    let (default_ipv4, default_ipv6) = match host_ip {
        IpAddr::V4(v4) => (v4.to_string(), String::new()),
        IpAddr::V6(v6) => (String::new(), v6.to_string()),
    };
    let spawned_container = GenericImage::new("ghcr.io/letsencrypt/pebble-challtestsrv", "latest")
        .with_wait_for(WaitFor::message_on_stdout(
            "Starting management server on :8055",
        ))
        // map these ports statically - this unfortunately can cause port clashes (simultaneous test runs, other apps),
        // but it's the easiest way to ensure that pebble can reach the challtestsrv on the proper validation port
        .with_mapped_port(http_port.as_u16(), http_port)
        .with_mapped_port(management_port.as_u16(), management_port)
        .with_mapped_port(dns_port.as_u16(), dns_port)
        .with_cmd(["-defaultIPv4", &default_ipv4, "-defaultIPv6", &default_ipv6])
        .start()
        .await
        .context("Failed to start challtestsrv")?;
    Ok(ChallengeTestServerContainer::new(
        management_port.as_u16(),
        http_port.as_u16(),
        dns_port.as_u16(),
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

    #[allow(dead_code)]
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
}

/// Find this host's IP address on any external interface
pub async fn get_host_ip() -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // Doesn't actually send any packets, just for routing purposes
    socket.connect("8.8.8.8:80").await?;
    socket.local_addr().map(|addr| addr.ip())
}
