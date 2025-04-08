use crate::Identifier;
use crate::acme::object::InnerChallenge;
use crate::challenge_solver::ChallengeSolver;
use crate::crypto::jws::JsonWebKey;
use anyhow::{Context, Error, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::warn;
use url::Url;

pub struct Solver {
    client: Client,
    registration: Registration,
}

impl Solver {
    pub fn new(client: Client, registration: Registration) -> Self {
        Self {
            client,
            registration,
        }
    }
}

#[async_trait]
impl ChallengeSolver for Solver {
    fn long_name(&self) -> &'static str {
        "acme-dns challenge solver"
    }

    fn short_name(&self) -> &'static str {
        "acme-dns"
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
        if let InnerChallenge::Dns(challenge) = challenge {
            let token = challenge.get_key_authorization(jwk);
            if let Some(identifier) = identifier.as_ascii_domain_name() {
                if identifier != self.registration.full_domain {
                    warn!(
                        "This solver is setup to solve the DNS-01 challenge using the domain {}, but the CNAME points to {identifier}. Did you remove or modify the CNAME?",
                        self.registration.full_domain
                    );
                    // Proceed anyway, maybe our view of the world isn't correct
                }
            }
            self.client.update_txt(&self.registration, token).await?;
            Ok(())
        } else {
            bail!("Unsupported challenge type for acme-dns");
        }
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        Ok(())
    }
}

pub struct Client {
    server_url: Url,
    client: reqwest::Client,
}

impl Client {
    pub fn new(server_url: Url, client: reqwest::Client) -> Self {
        Self { server_url, client }
    }

    pub async fn register(
        &self,
        allow_from: impl Iterator<Item = IpAddr>,
    ) -> Result<CreatedRegistration, Error> {
        let body = RegistrationBody {
            allow_from: allow_from.collect(),
        };
        let response = self
            .client
            .post(self.server_url.join("register")?)
            .json(&body)
            .send()
            .await
            .context(format!(
                "Registering new account at ACME-DNS server {}",
                self.server_url
            ))?;
        Ok(response
            .error_for_status()
            .context(format!(
                "Registering new account at ACME-DNS server {}",
                self.server_url
            ))?
            .json()
            .await?)
    }

    pub async fn update_txt(
        &self,
        registration: &Registration,
        value: String,
    ) -> Result<(), Error> {
        let body = UpdateBody {
            subdomain: registration.subdomain.clone(),
            txt: value,
        };
        self.client
            .post(self.server_url.join("update")?)
            .header("X-Api-User", registration.username.as_str())
            .header("X-Api-Key", registration.password.as_str())
            .json(&body)
            .send()
            .await
            .context(format!(
                "Updating TXT record at ACME-DNS server {}",
                self.server_url
            ))?
            .error_for_status()
            .context(format!(
                "Updating TXT record at ACME-DNS server {}",
                self.server_url
            ))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    full_domain: String,
    subdomain: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct RegistrationBody {
    #[serde(rename = "allowfrom")]
    allow_from: Vec<IpAddr>,
}

#[derive(Debug, Deserialize)]
pub struct CreatedRegistration {
    #[serde(rename = "allowfrom")]
    pub allow_from: Vec<IpAddr>,
    #[serde(rename = "fulldomain")]
    pub full_domain: String,
    pub password: String,
    pub subdomain: String,
    pub username: String,
}

impl From<CreatedRegistration> for Registration {
    fn from(registration: CreatedRegistration) -> Self {
        Self {
            full_domain: registration.full_domain,
            subdomain: registration.subdomain,
            username: registration.username,
            password: registration.password,
        }
    }
}

#[derive(Debug, Serialize)]
struct UpdateBody {
    subdomain: String,
    txt: String,
}
