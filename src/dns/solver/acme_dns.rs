use crate::acme::object::InnerChallenge;
use crate::challenge_solver::{ChallengeSolver, SolverCategory, SolverConfigBuilder};
use crate::cli::CommandLineSolverConfiguration;
use crate::config::{AcmeDnsConfiguration, SolverConfiguration};
use crate::crypto::jws::JsonWebKey;
use crate::interactive::editor::{ClosureEditor, InteractiveConfigEditor};
use crate::url::Url;
use crate::{Identifier, USER_AGENT};
use anyhow::{Context, Error, bail};
use async_trait::async_trait;
use clap::{Args, Command, CommandFactory, FromArgMatches, Parser};
use futures::FutureExt;
use inquire::PasswordDisplayMode;
use inquire::validator::Validation;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::warn;

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

    pub fn try_from_config(config: AcmeDnsConfiguration) -> anyhow::Result<Box<Self>> {
        let client = Client::new_with_default_transport(config.server)?;
        Ok(Box::new(Self::new(client, config.registration)))
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
        // There is a 1s TTL on acme-dns records. Sleep 1s+1s margin to avoid very tight races
        // in case we do another acme-dns challenge right after this one
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    server_url: Url,
    client: reqwest::Client,
}

impl Client {
    pub fn new(server_url: Url, client: reqwest::Client) -> Self {
        Self { server_url, client }
    }

    pub fn new_with_default_transport(server_url: Url) -> anyhow::Result<Self> {
        // TODO: Reuse HTTP client from somewhere?
        let reqwest_client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;
        Ok(Self::new(server_url, reqwest_client))
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
            .post(self.server_url.join("register")?.into_url())
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
            .post(self.server_url.join("update")?.into_url())
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Args)]
pub struct Registration {
    /// The full domain received from the acme-dns server during registration
    #[clap(long)]
    pub full_domain: String,
    /// The subdomain part from the registration
    #[clap(long)]
    pub subdomain: String,
    /// API username received during registration
    #[clap(long)]
    pub username: String,
    /// API password (or API key) received during registration
    #[clap(long)]
    pub password: String,
}

impl Display for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "acme-dns registration:\n  Full domain: {}\n  Subdomain: {}\n  Username: {}\n  Password: {}",
            self.full_domain, self.subdomain, self.username, self.password
        )
    }
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

#[derive(Debug, Clone, Default)]
pub struct Builder {}

impl Builder {
    pub fn user_ask_server() -> anyhow::Result<Url> {
        inquire::CustomType::<Url>::new("Enter the API URL of your acme-dns server")
            .with_default(Url::from_str("https://auth.acme-dns.io")?)
            .with_help_message("Refer to acme-dns documentation at https://github.com/joohoi/acme-dns for how to setup your own instance")
            .with_validator(|url: &Url| {
                if url.scheme() != "http" && url.scheme() != "https" {
                    Ok(Validation::Invalid("Must be a HTTP(S) URL".into()))
                } else {
                    Ok(Validation::Valid)
                }
            })
            .with_error_message("Enter a valid URL")
            .prompt()
            .context("No answer to acme-dns server prompt")
    }

    pub async fn user_ask_registration(client: &Client) -> anyhow::Result<Registration> {
        let new_registration = inquire::Confirm::new("Create a fresh registration?")
            .with_default(true)
            .prompt()
            .context("No answer to new registration prompt")?;

        let registration: Registration = if new_registration {
            client
                .register(std::iter::empty())
                .await
                .context(format!(
                    "Failed to register new account at acme-dns server {}",
                    client.server_url
                ))?
                .into()
        } else {
            let dummy_registration = Registration {
                full_domain: String::new(),
                subdomain: String::new(),
                username: String::new(),
                password: String::new(),
            };
            InteractiveConfigEditor::new(
                "Fill out all fields",
                dummy_registration,
                [
                    ClosureEditor::new(
                        "Full domain",
                        |registration: &Registration| registration.full_domain.as_str().into(),
                        |mut config: Registration| async {
                            config.full_domain = inquire::Text::new("Enter the full domain (subdomain + acme-dns base domain) received during registration")
                                .with_initial_value(&config.full_domain).prompt().context("No answer to full domain dialog")?;
                            Ok(config)
                        }.boxed(),
                    ),
                    ClosureEditor::new(
                        "Subdomain",
                        |registration: &Registration| registration.subdomain.as_str().into(),
                        |mut config: Registration| async {
                            config.subdomain = inquire::Text::new("Enter the subdomain received during registration (usually first part of full domain)")
                                .with_initial_value(&config.subdomain).prompt().context("No answer to subdomain dialog")?;
                            Ok(config)
                        }.boxed(),
                    ),
                    ClosureEditor::new(
                        "Username",
                        |registration: &Registration| registration.username.as_str().into(),
                        |mut config: Registration| async {
                            config.username = inquire::Text::new("Enter the username received during registration")
                                .with_initial_value(&config.username).prompt().context("No answer to username dialog")?;
                            Ok(config)
                        }.boxed(),
                    ),
                    ClosureEditor::new(
                        "Password",
                        |registration: &Registration| registration.password.chars().map(|_| '*').collect(),
                        |mut config: Registration| async {
                            config.password = inquire::Password::new("Enter the password (or API-Key) received during registration")
                                .with_display_mode(PasswordDisplayMode::Masked).prompt().context("No answer to password dialog")?;
                            Ok(config)
                        }.boxed(),
                    ),
                ]
                    .into_iter(),
                |registration: &Registration| {
                    async {
                        if registration.full_domain.is_empty() || registration.subdomain.is_empty() || registration.username.is_empty() || registration.password.is_empty() {
                            println!("Error: No registration field may be empty");
                            Ok(false)
                        } else {
                            Ok(true)
                        }
                    }.boxed()
                },
            )
                .edit_config()
                .await?
        };
        println!("Using acme-dns registration:\n{registration}");
        Ok(registration)
    }
}

/// acme-dns (<https://github.com/joohoi/acme-dns>) solves the dns challenge for any domain by redirecting the challenge domain to an ACME-DNS server. Requires an acme-dns installation.
#[derive(Debug, Parser)]
#[command(about, name = "acme-dns")]
struct CommandLineArgs {
    #[clap(long)]
    /// API URL of the acme-dns instance
    server: Url,
    #[clap(flatten)]
    registration: Registration,
}

#[async_trait]
impl SolverConfigBuilder for Builder {
    fn new() -> Box<Self>
    where
        Self: Sized,
    {
        Box::new(Self::default())
    }

    fn name(&self) -> &'static str {
        "acme-dns"
    }

    fn description(&self) -> &'static str {
        "acme-dns (https://github.com/joohoi/acme-dns) solves the dns challenge for any domain by redirecting the challenge domain to an ACME-DNS server. Requires an acme-dns installation."
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Dns
    }

    fn preference(&self) -> usize {
        40
    }

    fn supported(&self, domains: &HashSet<Identifier>) -> bool {
        domains
            .iter()
            .all(|domain| matches!(domain, Identifier::Dns(_)))
    }

    async fn build_interactive(
        &self,
        domains: &HashSet<Identifier>,
    ) -> anyhow::Result<SolverConfiguration> {
        if !self.supported(domains) {
            bail!("The acme-dns solver can only be used with domain names");
        }
        let server = Self::user_ask_server()?;
        let client = Client::new_with_default_transport(server.clone())?;
        println!(
            "You can provide an existing acme-dns account/registration if you want, or create a fresh one now."
        );
        let registration = Self::user_ask_registration(&client).await?;
        let mut challenge_domains = HashSet::new();
        for domain in domains {
            #[allow(irrefutable_let_patterns)]
            if let Identifier::Dns(domain) = domain {
                challenge_domains.insert(domain.to_acme_challenge_name()?);
            } else {
                bail!("Identifier {domain} is not a domain name and cannot be used for acme-dns");
            }
        }
        let target_domain = registration.full_domain.clone();
        loop {
            println!(
                "Please add the following CNAME records now in your DNS provider's zone management. You only need to do this once. The CNAMEs should remain there permanently."
            );
            for challenge_domain in &challenge_domains {
                let challenge_domain = challenge_domain.as_ascii();
                println!("{challenge_domain}. IN CNAME {target_domain}.");
            }
            let confirm = inquire::Confirm::new(
                "Confirm that you have added or verified that the above CNAME records all exist",
            )
            .with_default(false)
            .prompt()
            .context("No confirmation given")?;
            if confirm {
                break;
            }
        }
        // TODO: Validate CNAMEs are actually in place?
        Ok(SolverConfiguration::AcmeDns(AcmeDnsConfiguration {
            registration,
            server,
        }))
    }

    async fn build_from_command_line(
        &self,
        cmd_line_config: &CommandLineSolverConfiguration,
    ) -> anyhow::Result<SolverConfiguration> {
        let args = CommandLineArgs::from_arg_matches(&cmd_line_config.matches)?;
        Ok(SolverConfiguration::AcmeDns(AcmeDnsConfiguration {
            registration: args.registration,
            server: args.server,
        }))
    }

    fn get_command_line(&self) -> Command {
        CommandLineArgs::command()
    }
}
