use crate::acme::object::Identifier;
use crate::config::{AccountConfiguration, CertificateAuthorityConfiguration};
use crate::crypto::signing::{Curve, KeyType};
use crate::pebble::ChallengeTestHttpSolver;
use crate::{
    build_cert_config, config, AcmeAccount, AcmeIssuer, AcmeIssuerWithAccount, Authorizer, Certonaut, IssueCommand,
    NewAccountOptions, CRATE_NAME,
};
use anyhow::{anyhow, bail, Context, Error};
use crossterm::style::Stylize;
use inquire::validator::Validation;
use inquire::{Confirm, Select, Text};
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt::Display;
use url::Url;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct InteractiveClient {
    client: Certonaut,
}

impl InteractiveClient {
    pub fn new(client: Certonaut) -> Self {
        Self { client }
    }

    pub async fn interactive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!("{}", format!("{CRATE_NAME} guided certificate issuance").green());
        let issuer = self.user_select_ca_and_account(&issue_cmd).await?;
        let domains = Self::user_ask_cert_domains(&issue_cmd)?;
        let cert_key = rcgen::KeyPair::generate().context("Generating new certificate key")?;
        let mut authorizers = Vec::with_capacity(domains.len());
        for domain in domains.into_iter().sorted() {
            authorizers.push(Authorizer::new(domain, ChallengeTestHttpSolver::default()));
        }
        let cert_config = build_cert_config(&issuer, authorizers.iter());
        let cert = issuer
            .issue(&cert_key, None, authorizers)
            .await
            .context("Issuing certificate")?;
        println!("Got a certificate!");
        config::save_certificate_and_config("my-cert", &cert_config, &cert_key, &cert)?;
        Ok(())
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

    async fn user_select_ca_and_account(&mut self, issue_cmd: &IssueCommand) -> Result<AcmeIssuerWithAccount, Error> {
        let issuer = if let Some(preselected_ca) = &issue_cmd.ca {
            preselected_ca.clone()
        } else {
            match Self::user_select_ca(&self.client)? {
                CaChoice::ExistingCa(ca) => ca.identifier,
                CaChoice::NewCa => {
                    let new_ca = Self::user_create_ca(&mut self.client)?;
                    let id = new_ca.identifier.clone();
                    self.client.add_new_ca(new_ca)?;
                    id
                }
            }
        };

        let account = if let Some(preselected_account) = &issue_cmd.account {
            preselected_account.clone()
        } else {
            let issuer = self.client.get_ca(&issuer).ok_or(anyhow!("CA {issuer} not found"))?;
            let ca_id = issuer.config.identifier.clone();
            match Self::user_select_account(issuer)? {
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

        self.client
            .get_ca(&issuer)
            .ok_or(anyhow!("CA {issuer} not found"))?
            .with_account(&account)
            .ok_or(anyhow!("Account {account} not found"))
    }

    fn user_select_ca(client: &Certonaut) -> Result<CaChoice, Error> {
        let configured_ca_list = &client.issuers;
        if configured_ca_list.is_empty() {
            return Ok(CaChoice::NewCa);
        }
        let mut choices = configured_ca_list
            .values()
            .map(|ca| &ca.config)
            .cloned()
            .map(CaChoice::ExistingCa)
            .collect::<Vec<_>>();
        choices.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        choices.push(CaChoice::NewCa);
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

    fn user_select_account(ca: &AcmeIssuer) -> Result<AccountChoice, Error> {
        let configured_accounts_list = &ca.accounts;
        if configured_accounts_list.is_empty() {
            return Ok(AccountChoice::NewAccount);
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
        choices.push(AccountChoice::NewAccount);
        println!("You have multiple account configured for this CA");
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
            "You can provide one or more contact addresses to the CA. This is optional, but
doing so may allow the CA to contact you in case of problems. Please provide a comma-separated list
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
                    "This CA indicates that you need a separate account, not managed by
{CRATE_NAME}, to use it. If you have such an external account,
{ca_name} will have given you instructions how to perform \"external account binding\" (EAB).
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
