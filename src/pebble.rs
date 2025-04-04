use crate::acme::object::{HttpChallenge, InnerChallenge, Token};
use crate::config::PebbleHttpSolverConfiguration;
use crate::crypto::jws::JsonWebKey;
use crate::{ChallengeSolver, Identifier};
use anyhow::{Context, Error, bail};
use async_trait::async_trait;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;
use url::Url;

const PEBBLE_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIIJOLbes8sTr4wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMTcx
MjA2MTk0MjEwWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAyNGUyZGIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5WgZNoVJandj43kkLyU50vzCZ
alozvdRo3OFiKoDtmqKPNWRNO2hC9AUNxTDJco51Yc42u/WV3fPbbhSznTiOOVtn
Ajm6iq4I5nZYltGGZetGDOQWr78y2gWY+SG078MuOO2hyDIiKtVc3xiXYA+8Hluu
9F8KbqSS1h55yxZ9b87eKR+B0zu2ahzBCIHKmKWgc6N13l7aDxxY3D6uq8gtJRU0
toumyLbdzGcupVvjbjDP11nl07RESDWBLG1/g3ktJvqIa4BWgU2HMh4rND6y8OD3
Hy3H8MY6CElL+MOCbFJjWqhtOxeFyZZV9q3kYnk9CAuQJKMEGuN4GU6tzhW1AgMB
AAGjRTBDMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAF85v
d40HK1ouDAtWeO1PbnWfGEmC5Xa478s9ddOd9Clvp2McYzNlAFfM7kdcj6xeiNhF
WPIfaGAi/QdURSL/6C1KsVDqlFBlTs9zYfh2g0UXGvJtj1maeih7zxFLvet+fqll
xseM4P9EVJaQxwuK/F78YBt0tCNfivC6JNZMgxKF59h0FBpH70ytUSHXdz7FKwix
Mfn3qEb9BXSk0Q3prNV5sOV3vgjEtB4THfDxSz9z3+DepVnW3vbbqwEbkXdk3j82
2muVldgOUgTwK8eT+XdofVdntzU/kzygSAtAQwLJfn51fS1GvEcYGBc1bDryIqmF
p9BI7gVKtWSZYegicA==
-----END CERTIFICATE-----";

pub fn pebble_root() -> reqwest::Result<reqwest::Certificate> {
    reqwest::Certificate::from_pem(PEBBLE_ROOT_PEM.as_bytes())
}

#[derive(Debug)]
pub struct ChallengeTestHttpSolver {
    test_client: ChallengeTestServerClient,
    challenge: Option<HttpChallenge>,
}

impl ChallengeTestHttpSolver {
    pub fn from_config(config: PebbleHttpSolverConfiguration) -> Box<Self> {
        Box::new(Self {
            challenge: None,
            test_client: ChallengeTestServerClient::new(config.base_url),
        })
    }
}

#[async_trait]
impl ChallengeSolver for ChallengeTestHttpSolver {
    fn long_name(&self) -> &'static str {
        "pebble-challtestsrv http-01 solver"
    }

    fn short_name(&self) -> &'static str {
        "pebble-http"
    }

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Http(_))
    }

    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        _identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        if let InnerChallenge::Http(http_challenge) = challenge {
            let token = http_challenge.get_token();
            let authorization = http_challenge.get_key_authorization(jwk);
            self.test_client
                .add_http_01_token(token, authorization)
                .await?;
            self.challenge = Some(http_challenge);
            Ok(())
        } else {
            bail!("Unsupported challenge type {}", challenge.get_type())
        }
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        if let Some(challenge) = self.challenge {
            self.test_client
                .remove_http_01_token(&challenge.token)
                .await
        } else {
            bail!("No challenge to cleanup")
        }
    }
}

#[derive(Debug)]
pub struct ChallengeTestDnsSolver {
    test_client: ChallengeTestServerClient,
    identifier: Option<String>,
}

impl ChallengeTestDnsSolver {
    pub fn new(url: Url) -> Box<Self> {
        Box::new(Self {
            test_client: ChallengeTestServerClient::new(url),
            identifier: None,
        })
    }
}

#[async_trait]
impl ChallengeSolver for ChallengeTestDnsSolver {
    fn long_name(&self) -> &'static str {
        "pebble-challtestsrv dns-01 solver"
    }

    fn short_name(&self) -> &'static str {
        "pebble-dns"
    }

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Dns(_))
    }

    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        if let InnerChallenge::Dns(dns_challenge) = challenge {
            let authorization = dns_challenge.get_key_authorization(jwk);
            let host = identifier
                .as_ascii_domain_name()
                .context(format!("{identifier} cannot be used for dns challenge"))?;
            // Pebble-challtestsrv requires a period at the end
            let host = format!("{host}.");
            debug!("Setting TXT value {authorization} for host {host}");
            self.test_client
                .add_dns_txt_record(&host, authorization)
                .await?;
            self.identifier = Some(host);
            Ok(())
        } else {
            bail!("Unsupported challenge type {}", challenge.get_type())
        }
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        if let Some(host) = self.identifier {
            self.test_client.remove_dns_txt_record(&host).await
        } else {
            bail!("No challenge to cleanup")
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeTestServerClient {
    base_url: Url,
    client: reqwest::Client,
}

impl ChallengeTestServerClient {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    async fn post<B: Serialize>(&self, path: &str, body: &B) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.base_url.join(path)?)
            .json(body)
            .send()
            .await?;
        response.error_for_status()?;
        Ok(())
    }

    pub async fn add_http_01_token(&self, token: &Token, content: String) -> anyhow::Result<()> {
        self.post(
            "add-http01",
            &ChallTestHttpBody {
                token,
                content: Some(content),
            },
        )
        .await
    }

    pub async fn remove_http_01_token(&self, token: &Token) -> anyhow::Result<()> {
        self.post(
            "del-http01",
            &ChallTestHttpBody {
                token,
                content: None,
            },
        )
        .await
    }

    pub async fn add_dns_txt_record(&self, host: &str, value: String) -> anyhow::Result<()> {
        self.post(
            "set-txt",
            &ChallTestDnsBody {
                host,
                value: Some(value),
            },
        )
        .await
    }

    pub async fn remove_dns_txt_record(&self, host: &str) -> anyhow::Result<()> {
        self.post("clear-txt", &ChallTestDnsBody { host, value: None })
            .await
    }

    pub async fn add_ipv4_address(&self, host: &str, address: Ipv4Addr) -> anyhow::Result<()> {
        self.post(
            "add-a",
            &MockHostIpAddr {
                host,
                addresses: vec![IpAddr::V4(address)],
            },
        )
        .await
    }

    pub async fn remove_ipv4_address(&self, host: &str) -> anyhow::Result<()> {
        self.post(
            "clear-a",
            &MockHostIpAddr {
                host,
                addresses: Vec::new(),
            },
        )
        .await
    }

    pub async fn add_ipv6_address(&self, host: &str, address: Ipv6Addr) -> anyhow::Result<()> {
        self.post(
            "add-aaaa",
            &MockHostIpAddr {
                host,
                addresses: vec![IpAddr::V6(address)],
            },
        )
        .await
    }

    pub async fn remove_ipv6_address(&self, host: &str) -> anyhow::Result<()> {
        self.post(
            "clear-aaaa",
            &MockHostIpAddr {
                host,
                addresses: Vec::new(),
            },
        )
        .await
    }

    pub async fn add_http_redirect(&self, path: &str, target: Url) -> anyhow::Result<()> {
        self.post(
            "add-redirect",
            &HttpRedirectBody {
                path,
                target_url: Some(target),
            },
        )
        .await
    }

    pub async fn remove_http_redirect(&self, path: &str) -> anyhow::Result<()> {
        self.post(
            "del-redirect",
            &HttpRedirectBody {
                path,
                target_url: None,
            },
        )
        .await
    }

    pub async fn set_default_ipv4(&self, ip: Ipv4Addr) -> anyhow::Result<()> {
        self.post("set-default-ipv4", &IpAddrBody { ip: IpAddr::V4(ip) })
            .await
    }

    pub async fn set_default_ipv6(&self, ip: Ipv6Addr) -> anyhow::Result<()> {
        self.post("set-default-ipv6", &IpAddrBody { ip: IpAddr::V6(ip) })
            .await
    }
}

#[derive(Serialize)]
struct ChallTestHttpBody<'a> {
    token: &'a Token,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}

#[derive(Serialize)]
struct ChallTestDnsBody<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Serialize)]
struct MockHostIpAddr<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<IpAddr>,
}

#[derive(Serialize)]
struct HttpRedirectBody<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "targetURL")]
    target_url: Option<Url>,
}

#[derive(Serialize)]
struct IpAddrBody {
    ip: IpAddr,
}
