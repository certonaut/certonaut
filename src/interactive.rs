use crate::acme::object::Identifier;
use crate::challenge_solver::{
    BuiltSolverConfiguration, SolverCategory, SolverConfigBuilder, CHALLENGE_SOLVER_REGISTRY,
};
use crate::cli::{CommandLineKeyType, IssueCommand};
use crate::config::{
    AccountConfiguration, CertificateAuthorityConfiguration, IdentifierConfiguration, SolverConfiguration,
};
use crate::crypto::asymmetric;
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::{
    build_cert_config, config, AcmeAccount, AcmeIssuer, AcmeIssuerWithAccount, AdvancedIssueConfiguration, Authorizer,
    Certonaut, NewAccountOptions, ParsedDuration, CRATE_NAME,
};
use anyhow::{anyhow, bail, Context, Error};
use crossterm::style::Stylize;
use inquire::validator::Validation;
use inquire::{Confirm, CustomType, Editor, Select, Text};
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use strum::VariantArray;
use toml_edit::DocumentMut;
use tracing::warn;
use url::Url;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct InteractiveService {
    client: Certonaut,
}

impl InteractiveService {
    pub fn new(client: Certonaut) -> Self {
        Self { client }
    }

    pub async fn interactive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!("{}", format!("{CRATE_NAME} interactive certificate issuance").green());
        let (issuer, account) = self.user_select_ca_and_account(&issue_cmd).await?;
        let issuer = self.client.get_issuer_with_account(&issuer, &account)?;
        let ca_name = issuer.issuer.config.name.to_string();
        // TODO: Detect if we already have this exact set of domains, or a subset of it and offer options depending on that.
        let domains = Self::user_ask_cert_domains(&issue_cmd)?;
        let authorizers = Self::user_ask_authorizers(&issuer, &issue_cmd, domains)?;
        let cert_display_name = self.user_ask_cert_name(&issue_cmd, &authorizers)?;
        let cert_id = self.client.choose_cert_id_from_display_name(&cert_display_name);
        let advanced_config = Self::user_ask_advanced_options(&issuer, &issue_cmd)?;
        let cert_config = build_cert_config(cert_display_name, &advanced_config, &issuer, authorizers.iter());
        let key_type = cert_config.key_type;
        let cert_key = asymmetric::new_key(key_type)
            .and_then(asymmetric::KeyPair::to_rcgen_keypair)
            .context(format!("Could not generate certificate key with type {key_type}"))?;
        let cert = issuer
            .issue(&cert_key, cert_config.lifetime, authorizers)
            .await
            .context(format!("Issuing certificate with CA {ca_name}"))?;
        println!("Got a certificate!");
        config::save_certificate_and_config(&cert_id, &cert_config, &cert_key, &cert)?;
        Ok(())
    }

    pub async fn interactive_add_ca(&mut self) -> Result<(), Error> {
        let new_ca = Self::user_create_ca(&mut self.client)?;
        let ca_id = new_ca.identifier.clone();
        self.client.add_new_ca(new_ca)?;
        let issuer = self
            .client
            .get_ca(&ca_id)
            .ok_or(anyhow!("Freshly created CA not found"))?;
        Certonaut::print_issuer(issuer).await;
        println!("Successfully added new certificate authority");
        Ok(())
    }

    pub async fn interactive_create_account(&mut self) -> Result<(), Error> {
        let ca_id = self.interactive_select_ca(true)?;
        let issuer = self.client.get_ca(&ca_id).ok_or(anyhow!("CA not found"))?;
        let new_account = Self::user_create_account(issuer).await?;
        let acc_id = new_account.config.identifier.clone();
        self.client.add_new_account(&ca_id, new_account)?;
        let account = self.client.get_issuer_with_account(&ca_id, &acc_id)?;
        Certonaut::print_account(&account).await;
        println!("Successfully added new account");
        Ok(())
    }

    pub async fn interactive_remove_ca(&mut self) -> Result<(), Error> {
        let ca_id = self.interactive_select_ca(false)?;
        let issuer = self.client.get_ca(&ca_id).ok_or(anyhow!("CA not found"))?;
        println!("You have selected this CA for deletion:");
        Certonaut::print_issuer(issuer).await;
        let delete = Confirm::new("Are you sure you want to remove this CA from configuration?")
            .with_default(false)
            .prompt()
            .context("No answer to deletion prompt")?;
        // TODO: Check if there are existing accounts or certs referencing the CA
        if delete {
            self.client.remove_ca(&ca_id)?;
            println!("Successfully removed CA from configuration");
        } else {
            println!("Aborting removal.");
        }
        Ok(())
    }

    pub async fn interactive_delete_account(&mut self) -> Result<(), Error> {
        let ca_choice = Self::user_select_ca(&self.client, false)?;
        let ca = if let CaChoice::ExistingCa(config) = ca_choice {
            self.client.get_ca_mut(&config.identifier)
        } else {
            None
        }
        .ok_or(anyhow!("CA not found (are there any issuers configured?)"))?;
        let account_choice = Self::user_select_account(ca, false)?;
        let account = if let AccountChoice::ExistingAccount(config) = account_choice {
            ca.with_account(&config.identifier)
        } else {
            None
        }
        .ok_or(anyhow!(
            "No such account found at CA (are there any accounts for this CA?)"
        ))?;
        println!("You have selected the following account for {}", "deletion".red());
        Certonaut::print_account(&account).await;
        let delete = Confirm::new(
            "Are you sure you want to deactivate this account at the CA and remove it from configuration?",
        )
        .with_default(false)
        .prompt()
        .context("No answer to deletion prompt")?;
        // TODO: Verify whether any certs reference this account ID
        if delete {
            // First, deactivate account at CA
            if let Err(e) = account.deactivate_account().await {
                warn!("Account deactivation at CA failed: {e:#}");
                // TODO: Ask the user whether to proceed?
            } else {
                println!("Account deactivated.");
            }

            let issuer_id = account.issuer.config.identifier.clone();
            let account_id = account.account.config.identifier.clone();
            self.client.remove_account(&issuer_id, &account_id)?;
            println!("Successfully removed account from configuration");
        } else {
            println!("Aborting deletion");
        }
        Ok(())
    }

    fn interactive_select_ca(&mut self, allow_creation: bool) -> Result<String, Error> {
        Ok(match Self::user_select_ca(&self.client, allow_creation)? {
            CaChoice::ExistingCa(ca) => ca.identifier,
            CaChoice::NewCa => {
                let new_ca = Self::user_create_ca(&mut self.client)?;
                let id = new_ca.identifier.clone();
                self.client.add_new_ca(new_ca)?;
                id
            }
        })
    }

    fn user_ask_advanced_options(
        issuer: &AcmeIssuerWithAccount,
        issue_cmd: &IssueCommand,
    ) -> Result<AdvancedIssueConfiguration, Error> {
        let advanced = &issue_cmd.advanced;
        // TODO: We need to decide how to skip interactive prompts if arguments are provided via CLI
        println!("{CRATE_NAME} has several advanced features (key type, ACME profiles, ACME lifetime, key reuse) that you can configure.");
        println!(
            "However, they're geared towards advanced usage and do not need to be configured explicitly in many cases."
        );
        let configure_advanced = Confirm::new("Do you want to configure advanced features for this certificate?")
            .with_default(false)
            .prompt()
            .context("No answer to advanced confirmation prompt")?;

        if !configure_advanced {
            return Ok(advanced.clone());
        }

        let key_type = if let Some(key_type) = advanced.key_type {
            Some(key_type)
        } else {
            let default = CommandLineKeyType::default();
            println!("The new certificate can use one of the following supported cryptographic algorithms.");
            println!("Note that not all CAs may support all of the choices below - consult the CA documentation.");
            println!(
                "If you are unsure what to select, just select the default option. RSA is also a very common choice."
            );
            Select::new(
                "Choose a key type for the new certificate",
                CommandLineKeyType::VARIANTS.to_vec(),
            )
            .with_help_message(&format!("Press ESC to use default {default}"))
            .prompt_skippable()
            .context("No answer to key type prompt")?
        };

        let profile = if let Some(profile) = &advanced.profile {
            Some(profile.clone())
        } else {
            // TODO: Check ACME profiles, if any, and ask user
            None
        };

        let lifetime = if let Some(lifetime) = &issue_cmd.advanced.lifetime {
            Some(*lifetime)
        } else {
            println!("Some CAs allow you to request a specific lifetime for the certificate (within a certain allowed range).");
            println!("You can enter such a desired lifetime for the certificate here, or leave it blank to not request any particular lifetime for the certificate.");
            println!("Note that if the CA does not support this feature, or the requested value, issuance will fail.");
            println!("Consult the CA's documentation before using this feature.");
            // TODO: Consider using crate::parse_duration here, instead of restricting to hours
            CustomType::<ParsedDuration>::new("Select a lifetime for the certificate")
                .with_error_message("Please type a valid duration, like '15d 2 hours 37min'")
                .with_default(Duration::ZERO.into())
                .with_help_message("Press ESC or enter 0s to not use this feature")
                .prompt_skippable()
                .context("No answer to cert lifetime prompt")?
                .and_then(|duration| if duration.is_zero() { None } else { Some(*duration) })
        };

        // TODO: Reuse key

        Ok(AdvancedIssueConfiguration {
            key_type,
            profile,
            lifetime,
            reuse_key: false,
        })
    }

    fn user_ask_authorizers(
        issuer: &AcmeIssuerWithAccount,
        issue_cmd: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> Result<Vec<Authorizer>, Error> {
        let solver_config = if let Some(solver_config) = &issue_cmd.solver {
            let solver_config: SolverConfiguration = solver_config.clone().into();
            (domains, solver_config).into()
        } else {
            println!("{}", "To issue a certificate, most CA's require you to prove control over all identifiers included in the certificate.
There are several ways to do this, and the best method depends on your system and preferences.
Currently, the following challenge \"solvers\" are available to prove control:".blue());
            let mut solver_options: Vec<_> = CHALLENGE_SOLVER_REGISTRY
                .iter()
                .filter(|builder| builder.supported(&domains))
                .collect();
            let multi_solver_builder: Box<dyn SolverConfigBuilder> = MultiSolverBuilder::new();
            solver_options.push(&multi_solver_builder);
            // TODO: Warn if wildcards are present
            // ... or filter solvers by identifier, i.e. only offer DNS-01 challenges if a wildcard is present?
            // -> solvers can now also decide if they're supported based on domains (i.e. onion-solver only for onion domain)
            let single_solver_choice = Select::new("Select a solver to authenticate all identifiers:", solver_options)
                .prompt()
                .context("No answer to solver prompt")?;
            single_solver_choice.build_interactive(issuer, issue_cmd, domains)?
        };

        let mut authorizers = match solver_config {
            BuiltSolverConfiguration::SingleConfig((domains, solver_config)) => {
                let mut authorizers = Vec::with_capacity(domains.len());
                for domain in domains.into_iter().sorted() {
                    authorizers.push(Authorizer::new_boxed(domain, None, solver_config.clone().to_solver()?));
                }
                authorizers
            }
            BuiltSolverConfiguration::MultipleConfigs(authorizers) => authorizers,
        };
        authorizers.sort_by_key(|authorizer| authorizer.identifier.clone());
        Ok(authorizers)
    }

    fn user_ask_cert_name(&self, issue_cmd: &IssueCommand, authorizers: &Vec<Authorizer>) -> Result<String, Error> {
        if let Some(cert_name) = &issue_cmd.cert_name {
            return Ok(cert_name.clone());
        }
        let default_cert_name = self.client.choose_cert_name_from_authorizers(authorizers);
        println!("If you want, you can give your new certificate a name to identify it later:");
        let cert_name = Text::new("Name your certificate:")
            .with_placeholder(&default_cert_name)
            .with_help_message(&format!("Press ESC or leave empty to use default {default_cert_name}"))
            .prompt_skippable()
            .context("No answer to cert name prompt")?
            .map(|cert_name| {
                if cert_name.trim().is_empty() {
                    default_cert_name.clone()
                } else {
                    cert_name
                }
            })
            .unwrap_or(default_cert_name);
        Ok(cert_name)
    }

    fn user_ask_cert_domains(issue_cmd: &IssueCommand) -> Result<HashSet<Identifier>, Error> {
        if let Some(domains) = &issue_cmd.domains {
            return Ok(domains
                .iter()
                .map(|domain| Identifier::from(domain.trim().to_string()))
                .sorted()
                .collect());
        }
        loop {
            let domains_string = Text::new("Enter the domain name(s) for the new certificate:")
                .with_placeholder("example.com")
                .with_help_message("Separate multiple names with spaces, commas, or both.")
                .with_validator(|input: &str| {
                    if input.trim().is_empty() {
                        return Ok(Validation::Invalid("Domain cannot be empty".into()));
                    }
                    if input.split(',').any(|input| input.trim().is_empty()) {
                        return Ok(Validation::Invalid(format!("Domain {input} cannot be empty").into()));
                    }
                    if input
                        .split_whitespace()
                        .flat_map(|s| s.split(','))
                        .any(|input| input.starts_with('.') || input.ends_with('.'))
                    {
                        return Ok(Validation::Invalid(
                            format!("Domain {input} cannot start or end with a dot").into(),
                        ));
                    }
                    Ok(Validation::Valid)
                })
                .prompt()
                .context("No answer to domain prompt")?;
            let mut domains = domains_string
                .split_whitespace()
                .flat_map(|s| s.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<Identifier>().unwrap(/* Infallible */))
                .sorted()
                .collect::<HashSet<_>>();
            if domains.is_empty() {
                println!("Domain list cannot be empty!");
                continue;
            }
            if domains.len() == 1 {
                let domain = domains.iter().next().unwrap(/* Infallible */);
                if domain.as_str().starts_with("www.") {
                    let base_name =
                        Identifier::from(domain.as_str().strip_prefix("www.").unwrap(/* Infallible */).to_string());
                    let add_base_name = Confirm::new(&format!("It is common to also include {base_name} in certificates, so that visitors can use both. Do you want to add the base domain to your certificate?"))
                        .with_default(false)
                        .prompt_skippable()?.unwrap_or(false);
                    if add_base_name {
                        domains.insert(base_name);
                    }
                } else {
                    let www_name = Identifier::from("www.".to_string() + domain.as_str());
                    let add_www = Confirm::new(&format!("It is common to also include {www_name} in certificates, so that visitors can use both. Do you want to add the www subdomain to your certificate?"))
                        .with_default(false)
                        .prompt_skippable()?.unwrap_or(false);
                    if add_www {
                        domains.insert(www_name);
                    }
                }
            }
            let domain_names = domains.iter().sorted().join(", ");
            let confirm = Confirm::new(&format!(
                "You have selected the following domain names: {domain_names}. Is this correct?"
            ))
            .with_help_message(
                "Enter yes to proceed, or no to abort. If you abort you can enter the domain names again.",
            )
            .with_default(false)
            .prompt()?;
            if confirm {
                break Ok(domains);
            }
        }
    }

    async fn user_select_ca_and_account(&mut self, issue_cmd: &IssueCommand) -> Result<(String, String), Error> {
        let issuer = if let Some(preselected_ca) = &issue_cmd.ca {
            preselected_ca.clone()
        } else {
            self.interactive_select_ca(true)?
        };

        let account = if let Some(preselected_account) = &issue_cmd.account {
            preselected_account.clone()
        } else {
            let issuer = self.client.get_ca(&issuer).ok_or(anyhow!("CA {issuer} not found"))?;
            let ca_id = issuer.config.identifier.clone();
            match Self::user_select_account(issuer, true)? {
                AccountChoice::ExistingAccount(ac) => ac.identifier,
                AccountChoice::NewAccount => {
                    let new_account = Self::user_create_account(issuer)
                        .await
                        .context("Error while creating new account")?;
                    let account_id = new_account.config.identifier.clone();
                    self.client.add_new_account(&ca_id, new_account)?;
                    account_id
                }
            }
        };
        Ok((issuer, account))
    }

    fn user_select_ca(client: &Certonaut, allow_creation: bool) -> Result<CaChoice, Error> {
        let configured_ca_list = &client.issuers;
        if configured_ca_list.is_empty() {
            if allow_creation {
                return Ok(CaChoice::NewCa);
            }
            bail!("No issuers configured");
        }
        let mut choices = configured_ca_list
            .values()
            .map(|ca| &ca.config)
            .cloned()
            .map(CaChoice::ExistingCa)
            .collect::<Vec<_>>();
        choices.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        if allow_creation {
            choices.push(CaChoice::NewCa);
        }
        let default_ca = choices
            .iter()
            .enumerate()
            .find(|(_, ca)| match ca {
                CaChoice::ExistingCa(ca) => ca.default,
                CaChoice::NewCa => false,
            })
            .map(|(idx, choice)| (idx, choice.clone()));
        let mut ca_choice = Select::new("Select the Certificate Authority (CA) you want to use", choices);
        let user_choice = if let Some((default_index, default_ca)) = default_ca {
            let default_help = Select::<CaChoice>::DEFAULT_HELP_MESSAGE.unwrap();
            let default_ca_name = default_ca.to_string();
            let help_text = format!("{default_help}, ESC to use default ({default_ca_name})");
            ca_choice.help_message = Some(&help_text);
            ca_choice.starting_cursor = default_index;
            ca_choice
                .prompt_skippable()
                .map(|user_choice| user_choice.unwrap_or(default_ca))
        } else {
            ca_choice.prompt()
        }
        .context("No CA selected")?;
        Ok(user_choice)
    }

    fn user_create_ca(client: &mut Certonaut) -> Result<CertificateAuthorityConfiguration, Error> {
        println!("{}", "Adding a new certificate authority".dark_green());
        let ca_name = Text::new("Name for the new CA:")
            .prompt()
            .context("No answer for CA name")?;
        let ca_id = client.choose_ca_id_from_name(&ca_name);
        let acme_url = Text::new("ACME directory URL for new CA:")
            .with_validator(|candidate: &str| {
                Ok(match Url::parse(candidate) {
                    Ok(url) => {
                        // ACME mandates HTTPS.
                        if url.scheme() != "https" {
                            return Ok(Validation::Invalid("Must be a HTTPS URL".into()));
                        }
                        if url.cannot_be_a_base() {
                            return Ok(Validation::Invalid("URL must be absolute".into()));
                        }
                        Validation::Valid
                    }
                    Err(_) => Validation::Invalid("Not a valid URL".into()),
                })
            })
            .prompt()
            .context("No answer for ACME directory URL")?;
        let acme_url = Url::parse(&acme_url).context("Invalid URL")?;
        let public = Confirm::new("Is this a public CA?")
            .with_default(false)
            .with_help_message("Enter no for a private/enterprise CA, yes for others. This is used to control whether we run pre-issuance checks by default")
            .prompt_skippable().context("No answer to public CA question")?
            .unwrap_or(false);
        let testing = Confirm::new("Is this a CA used for testing?")
            .with_default(false)
            .with_help_message(
                "Enter no if this CA issues production-ready certs, yes if the certificates are meant for testing.",
            )
            .prompt_skippable()
            .context("No answer to test CA question")?
            .unwrap_or(false);
        let current_default = client.issuers.values().find(|ca| ca.config.default);
        let mut new_default_prompt = Confirm::new("Do you want to use this CA as your default?").with_default(false);
        let mut help_message = "You do not currently have any default CA set".to_string();
        if let Some(current_default) = current_default {
            help_message = format!(
                "Your current default CA is {}{}",
                current_default.config.name.as_str().green(),
                ". Entering yes will change the default to the new CA".cyan(),
            );
        }
        new_default_prompt = new_default_prompt.with_help_message(&help_message);
        let new_default = new_default_prompt
            .prompt_skippable()
            .context("No answer to default CA prompt")?
            .unwrap_or(false);
        if new_default {
            client.issuers.values_mut().for_each(|ca| ca.config.default = false);
        }
        Ok(CertificateAuthorityConfiguration {
            name: ca_name,
            identifier: ca_id,
            acme_directory: acme_url,
            public,
            testing,
            default: new_default,
        })
    }

    fn user_select_account(ca: &AcmeIssuer, allow_creation: bool) -> Result<AccountChoice, Error> {
        let configured_accounts_list = &ca.accounts;
        if configured_accounts_list.is_empty() {
            if allow_creation {
                return Ok(AccountChoice::NewAccount);
            }
            bail!("No accounts configured for CA {}", ca.config.name)
        }
        // If the user has only a single account, we select that by default
        // because that's a very common setup. The user can still request for new accounts to be
        // created explicitly.
        if configured_accounts_list.len() == 1 {
            return Ok(AccountChoice::ExistingAccount(
                ca.accounts.values().next().unwrap().config.clone(),
            ));
        }
        let mut choices = configured_accounts_list
            .values()
            .map(|account| &account.config)
            .cloned()
            .map(AccountChoice::ExistingAccount)
            .collect::<Vec<_>>();
        if allow_creation {
            choices.push(AccountChoice::NewAccount);
        }
        println!("You have multiple accounts configured for this CA");
        let user_choice = Select::new("Select the account you want to use", choices)
            .prompt()
            .context("No account selected")?;
        Ok(user_choice)
    }

    async fn user_create_account(ca: &AcmeIssuer) -> Result<AcmeAccount, Error> {
        let ca_name = ca.config.name.as_str().green();
        println!("Creating a new account at CA {ca_name}");
        let acme_client = ca.client().await?;
        let tos_status = Self::user_create_account_ca_specific_features(ca).await?;
        println!(
            "You can provide one or more contact addresses to the CA. This is optional, but \
doing so may allow the CA to contact you in case of problems. Please provide a comma-separated list \
of email addresses below, or leave the field empty to not provide any contact address to the CA."
        );
        let email_prompt = Text::new("Email(s):")
            .with_help_message("Enter an email address, or press ESC to leave empty. Comma-separate multiple addresses")
            .with_placeholder("email@example.com, another-address@example.org")
            .with_validator(|input: &str| {
                Ok(input
                    .split(',')
                    .map(|address| {
                        // Lax email validation. The CA may apply stricter requirements.
                        let address = address.trim();
                        if address.is_empty() {
                            // Empty addresses are valid, but skipped
                            return Validation::Valid;
                        }
                        let parts = address.split('@').collect::<Vec<_>>();
                        if parts.len() != 2 {
                            return Validation::Invalid(
                                (address.to_string() + " does not look like an email address").into(),
                            );
                        }
                        if !parts[1].contains('.') {
                            return Validation::Invalid(
                                (address.to_string() + " does not look like an email address").into(),
                            );
                        }
                        // There are still lots of possible invalid addresses here, but we don't know exactly
                        // what the CA will accept anyway.
                        Validation::Valid
                    })
                    .find(|validation| matches!(validation, Validation::Invalid(_)))
                    .unwrap_or(Validation::Valid))
            });
        let email_string = email_prompt
            .prompt_skippable()
            .context("No answer to email dialog")?
            .unwrap_or(String::new());
        let emails = email_string
            .split(',')
            .map(str::trim)
            .filter(|email| !email.is_empty())
            .map(|email| "mailto:".to_owned() + email)
            .collect::<Vec<_>>();
        let mut contacts = Vec::with_capacity(emails.len());
        for contact in emails {
            contacts.push(Url::try_from(contact.as_str()).context("Validating contact URL")?);
        }
        let ca_name = &ca.config.name;
        let ca_id = &ca.config.identifier;
        let account_num = ca.accounts.len();
        let account_name = if account_num > 0 {
            format!("{ca_name} ({account_num})")
        } else {
            ca_name.to_string()
        };
        let account_id = format!("{ca_id}@{account_num}");
        Certonaut::create_account(
            acme_client,
            NewAccountOptions {
                name: account_name,
                identifier: account_id,
                contacts,
                // TODO: We could try EdDSA keys first, check for a badSignatureError, and then retry with P256?
                key_type: KeyType::Ecdsa(Curve::P256),
                terms_of_service_agreed: tos_status,
            },
        )
        .await
    }

    async fn user_create_account_ca_specific_features(ca: &AcmeIssuer) -> anyhow::Result<Option<bool>> {
        let ca_name = ca.config.name.as_str().green();
        let acme_client = ca.client().await?;
        let directory = acme_client.get_directory();
        let mut tos_status = None;
        if let Some(meta) = &directory.meta {
            if let Some(website) = &meta.website {
                println!("If this is your first time using {ca_name}, you may want to review this website:",);
                println!("{}", website.as_str().blue());
            }
            if let Some(tos) = &meta.terms_of_service {
                println!("Please familiarize yourself with {ca_name} terms of service, available at this URL:",);
                println!("{}", tos.as_str().green().on_black());
                let tos_agreed = Confirm::new("Do you agree to these terms of service?")
                    .with_default(false)
                    .with_help_message("This may be required by the CA for account creation")
                    .prompt()
                    .context("No answer to TOS prompt")?;
                tos_status = Some(tos_agreed);
            }
            if meta.external_account_required {
                println!(
                    "This CA indicates that you need a separate account, not managed by \
{CRATE_NAME}, to use it. If you have such an external account, \
{ca_name} will have given you instructions how to perform \"external account binding\" (EAB). \
You may need to create an account at the CA's website first.",
                );
                let has_eab = Confirm::new(&format!(
                    "Do you have the {} and {} provided by the CA?",
                    "EAB_KID".dark_green().on_black(),
                    "EAB_HMAC_KEY".dark_green().on_black()
                ))
                .with_help_message(
                    "If not, please review the CA's website to find these. They are required to proceed.",
                )
                .with_default(false)
                .prompt()
                .context("No answer to EAB check-question")?;
                if has_eab {
                    todo!("EAB currently not implemented")
                } else {
                    bail!("EAB is required for this CA. Please review the CA's website to find instructions, or select a different CA.")
                }
            }
        }
        Ok(tos_status)
    }
}

#[derive(Debug, Clone)]
pub enum CaChoice {
    ExistingCa(CertificateAuthorityConfiguration),
    NewCa,
}

impl PartialEq for CaChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => {
                self_ca.identifier == other_ca.identifier
            }
            _ => false,
        }
    }
}

impl PartialOrd for CaChoice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => Some(self_ca.name.cmp(&other_ca.name)),
            _ => None,
        }
    }
}

impl Display for CaChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaChoice::ExistingCa(ca) => {
                let name = &ca.name;
                write!(f, "{name}")?;
                if ca.testing {
                    write!(f, " (Testing)")?;
                };
            }
            CaChoice::NewCa => write!(f, "Add new CA")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum AccountChoice {
    ExistingAccount(AccountConfiguration),
    NewAccount,
}

impl PartialEq for AccountChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AccountChoice::ExistingAccount(self_acc), AccountChoice::ExistingAccount(other_acc)) => {
                self_acc.identifier == other_acc.identifier
            }
            _ => false,
        }
    }
}

impl PartialOrd for AccountChoice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (AccountChoice::ExistingAccount(self_acc), AccountChoice::ExistingAccount(other_acc)) => {
                Some(self_acc.name.cmp(&other_acc.name))
            }
            _ => None,
        }
    }
}

impl Display for AccountChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountChoice::ExistingAccount(ca) => {
                let name = &ca.name;
                write!(f, "{name}")?;
            }
            AccountChoice::NewAccount => write!(f, "Create new account")?,
        }
        Ok(())
    }
}

impl Display for dyn SolverConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} - {}",
            self.category().to_string().blue(),
            self.name().dark_green(),
            self.description().reset()
        )
    }
}

struct MultiSolverBuilder {}

impl SolverConfigBuilder for MultiSolverBuilder {
    fn new() -> Box<Self>
    where
        Self: Sized,
    {
        Box::new(MultiSolverBuilder {})
    }

    fn name(&self) -> &'static str {
        "Multiple solvers"
    }

    fn description(&self) -> &'static str {
        "This option allows you to use different solvers for different identifiers"
    }

    fn category(&self) -> SolverCategory {
        SolverCategory::Advanced
    }

    fn preference(&self) -> usize {
        200
    }

    fn supported(&self, _domains: &HashSet<Identifier>) -> bool {
        true
    }

    fn build_interactive(
        &self,
        _issuer: &AcmeIssuerWithAccount,
        _issue_command: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        println!(
            "Multiple solvers can be specified directly in TOML format. A temporary file will be opened containing \
 a template that you can fill out. Please refer to the documentation at TODO for more information about the solvers."
        );
        let domain_template = domains
            .iter()
            .map(|id| format!("\"{id}\" = \"example-solver\""))
            .join("\n");
        let template = format!(
            "[domains]
# This section contains the domain names of your certificate.
# Each line has the domain name (quoted) on the left hand side, and the name of a solver on the right hand side.
# Every domain can have a different solver, or multiple domains can share a single solver configuration.
{domain_template}

# Every solver configuration is specified as solver.<solver-name>
[solver.example-solver]
# The solver is named \"example-solver\" and has the configuration as specified below
# Refer to TODO for documentation on the available solver types
type = \"webroot\"
# Refer to TODO about the available configuration options per solver
web_index = \"/var/www/html\""
        );
        let raw_toml = Editor::new("Solver configuration:")
            .with_file_extension(".toml")
            .with_predefined_text(&template)
            .with_help_message(
                "This prompt will open your default text editor to make changes to the provided template.",
            )
            .with_validator(move |content: &str| Ok(validate_solver_toml(&domains, content)))
            .prompt()
            .context("No answer to solver prompt")?;
        let toml = toml_edit::DocumentMut::from_str(&raw_toml).context("Parsing user specified TOML")?;
        let domains_table = toml
            .get("domains")
            .and_then(|domains| domains.as_table())
            .ok_or(anyhow!("No domains specified"))?;
        let mut domains = vec![];
        for (domain, solver) in domains_table {
            let solver_identifier = solver
                .as_str()
                .map(ToString::to_string)
                .ok_or(anyhow!("Domain value for key {domain} must be a string"))?;
            domains.push(IdentifierConfiguration {
                domain: domain.to_string(),
                solver_identifier,
            });
        }
        let solvers_table = toml
            .get("solver")
            .and_then(|solvers| solvers.as_table())
            .ok_or(anyhow!("No solvers specified"))?;
        let mut solvers = HashMap::new();
        for (solver, config) in solvers_table {
            let solver_config = config
                .as_table()
                .map(|config| toml_edit::DocumentMut::from(config.clone()))
                .ok_or(anyhow!("Solver {solver} is not a table"))?;
            let solver_config: SolverConfiguration = toml_edit::de::from_document(solver_config)
                .context(format!("Parsing solver configuration for {solver}"))?;
            solvers.insert(solver.to_string(), solver_config);
        }

        let mut authorizers = Vec::new();
        for identifier_config in domains {
            let solver_name = identifier_config.solver_identifier.as_str();
            let config = solvers
                .get(solver_name)
                .ok_or(anyhow!("Solver {solver_name} not found"))?;
            let solver = config.clone().to_solver()?;
            let authorizer = Authorizer::new_boxed(
                Identifier::from(identifier_config.domain),
                Some(solver_name.to_string()),
                solver,
            );
            authorizers.push(authorizer);
        }
        Ok(authorizers.into())
    }

    fn build_noninteractive(
        &self,
        _issuer: &AcmeIssuerWithAccount,
        _issue_command: &IssueCommand,
        _domains: HashSet<Identifier>,
    ) -> anyhow::Result<BuiltSolverConfiguration> {
        bail!("The multi solver builder can only be used interactively")
    }
}

fn validate_solver_toml(domains: &HashSet<Identifier>, content: &str) -> Validation {
    fn validate_err(domains: &HashSet<Identifier>, content: &str) -> Result<(), Validation> {
        let parsed_toml = toml_edit::DocumentMut::from_str(content)
            .map_err(|e| Validation::Invalid(format!("Invalid TOML syntax: {e}").into()))?;
        let user_domains = parsed_toml
            .get("domains")
            .and_then(|domains| domains.as_table())
            .ok_or(Validation::Invalid("Missing table \"domains\"".into()))?;
        for domain in domains {
            let solver_name = user_domains
                .get(domain.as_str())
                .and_then(|item| item.as_value())
                .and_then(|value| value.as_str())
                .ok_or(Validation::Invalid(
                    format!("Missing or invalid entry for {domain} in domains").into(),
                ))?;
            let solver = parsed_toml
                .get("solver")
                .and_then(|solvers| solvers.get(solver_name))
                .and_then(|solver| solver.as_table())
                .ok_or(Validation::Invalid(
                    format!("Missing or invalid table for {solver_name}").into(),
                ))?;
            let solver_document = DocumentMut::from(solver.clone());
            let _test_config: SolverConfiguration =
                toml_edit::de::from_document(solver_document).map_err(|toml_err| {
                    Validation::Invalid(format!("Solver {solver_name} is invalid: {toml_err}").into())
                })?;
        }
        Ok(())
    }

    match validate_err(domains, content) {
        Ok(()) => Validation::Valid,
        Err(validation) => validation,
    }
}
