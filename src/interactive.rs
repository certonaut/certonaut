use crate::acme::client::AcmeClient;
use crate::config::CertificateAuthorityConfiguration;
use crate::crypto::signing::{Curve, KeyType};
use crate::{
    new_acme_client, AccountChoice, AcmeAccount, AcmeIssuer, CaChoice, Certonaut, IssueCommand,
    NewAccountOptions, CRATE_NAME,
};
use anyhow::{bail, Context, Error};
use crossterm::style::Stylize;
use inquire::validator::Validation;
use inquire::{Confirm, Select, Text};
use std::sync::Arc;
use url::Url;

#[derive(Debug)]
pub struct InteractiveClient {
    client: Certonaut,
}

impl InteractiveClient {
    pub fn new(client: Certonaut) -> Self {
        Self { client }
    }

    pub async fn interactive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!(
            "{}",
            format!("{CRATE_NAME} guided certificate issuance")
                .green()
                .on_black()
        );
        let (client, account) = self.user_select_ca_and_account(&issue_cmd).await?;
        let issuer = AcmeIssuer::new(Arc::new(client), account);
        Ok(())
    }

    async fn user_select_ca_and_account(
        &mut self,
        issue_cmd: &IssueCommand,
    ) -> Result<(AcmeClient, AcmeAccount), Error> {
        let (ca_choice, account_choice) = self.client.select_ca_and_account(
            &issue_cmd.ca,
            &issue_cmd.account,
            |client| Self::user_select_ca(client),
            |_client, ca| Self::user_select_account(ca),
        )?;
        let ca = match ca_choice {
            CaChoice::ExistingCa(ca) => ca,
            CaChoice::NewCa => {
                let new_ca = Self::user_create_ca(&mut self.client).await?;
                self.client.save_new_ca(new_ca.clone())?;
                new_ca
            }
        };
        let account = match account_choice {
            AccountChoice::ExistingAccount(ac) => {
                AcmeAccount::load_existing(ac).context("Error loading ACME account")?
            }
            AccountChoice::NewAccount => {
                let new_account = Self::user_create_account(&ca)
                    .await
                    .context("Error while creating new account")?;
                self.client
                    .save_new_account(&ca.identifier, new_account.config.clone())?;
                new_account
            }
        };
        let acme_client = new_acme_client(&ca)
            .await
            .context("Establishing connection to CA failed")?;
        Ok((acme_client, account))
    }

    fn user_select_ca(client: &Certonaut) -> Result<CaChoice, Error> {
        let configured_ca = &client.config.ca_list;
        if configured_ca.is_empty() {
            return Ok(CaChoice::NewCa);
        }
        let mut choices = configured_ca
            .iter()
            .map(Clone::clone)
            .map(CaChoice::ExistingCa)
            .collect::<Vec<_>>();
        choices.push(CaChoice::NewCa);
        let default_ca = choices
            .iter()
            .enumerate()
            .find(|(_, ca)| match ca {
                CaChoice::ExistingCa(ca) => ca.default,
                _ => false,
            })
            .map(|(idx, choice)| (idx, choice.clone()));
        let mut ca_choice = Select::new(
            "Select the Certificate Authority (CA) you want to use",
            choices,
        );
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

    async fn user_create_ca(
        client: &mut Certonaut,
    ) -> Result<CertificateAuthorityConfiguration, Error> {
        println!("Add new CA");
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
            .with_help_message("Enter no if this CA issues production-ready certs")
            .prompt_skippable()
            .context("No answer to testing CA question")?
            .unwrap_or(false);
        let current_default = client.config.ca_list.iter().find(|ca| ca.default);
        let mut new_default_prompt =
            Confirm::new("Do you want to use this CA as your default?").with_default(false);
        let mut help_message = "You do not currently have any default CA set".to_string();
        if let Some(current_default) = current_default {
            help_message = format!(
                "Your current default CA is {}{}",
                current_default.name.as_str().green().on_black(),
                ". Entering yes will change the default to the new CA"
                    .cyan()
                    .on_black(),
            );
        }
        new_default_prompt = new_default_prompt.with_help_message(&help_message);
        let new_default = new_default_prompt
            .prompt_skippable()
            .context("No answer to default CA prompt")?
            .unwrap_or(false);
        if new_default {
            client
                .config
                .ca_list
                .iter_mut()
                .for_each(|ca| ca.default = false);
        }
        Ok(CertificateAuthorityConfiguration {
            name: ca_name,
            identifier: ca_id,
            acme_directory: acme_url,
            public,
            testing,
            default: new_default,
            accounts: vec![],
        })
    }

    fn user_select_account(ca: &CertificateAuthorityConfiguration) -> Result<AccountChoice, Error> {
        let configured_accounts = &ca.accounts;
        if configured_accounts.is_empty() {
            return Ok(AccountChoice::NewAccount);
        }
        // If the user has only a single account, we select that by default
        // because that's a very common setup. The user can still request for new accounts to be
        // created explicitly.
        if configured_accounts.len() == 1 {
            return Ok(AccountChoice::ExistingAccount(ca.accounts[0].clone()));
        }
        let mut choices = configured_accounts
            .iter()
            .map(Clone::clone)
            .map(AccountChoice::ExistingAccount)
            .collect::<Vec<_>>();
        choices.push(AccountChoice::NewAccount);
        println!("You have multiple account configured for this CA");
        let user_choice = Select::new("Select the account you want to use", choices)
            .prompt()
            .context("No account selected")?;
        Ok(user_choice)
    }

    async fn user_create_account(
        ca: &CertificateAuthorityConfiguration,
    ) -> Result<AcmeAccount, Error> {
        let ca_name = ca.name.as_str().green().on_black();
        let acme_client = new_acme_client(ca).await?;
        let directory = acme_client.get_directory();
        let mut tos_status = None;
        if let Some(meta) = &directory.meta {
            println!("Before we start account creation, some prerequisites to verify:");
            if let Some(website) = &meta.website {
                println!(
                    "If this is your first time using {}, you may want to review this website:",
                    ca_name
                );
                println!("{}", website.as_str().green().on_black());
            }
            if let Some(tos) = &meta.terms_of_service {
                println!(
                    "Please familiarize yourself with {} terms of service, available at this URL:",
                    ca_name
                );
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
{} will have given you instructions how to perform \"external account binding\" (EAB).
You may need to create an account at the CA's website first.",
                    ca_name
                );
                let has_eab = Confirm::new(
                    &format!("Do you have the {} and {} provided by the CA?",
                             "EAB_KID".dark_green().on_black(), "EAB_HMAC_KEY".dark_green().on_black()
                    ))
                    .with_help_message("If not, please review the CA's website to find these. They are required to proceed.")
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
        println!(
            "You can provide one or more contact addresses to the CA. This is optional, but
doing so may allow the CA to contact you in case of problems. Please provide a comma-separated list
of email addresses below, or leave the field empty to not provide any contact address to the CA."
        );
        let email_prompt = Text::new("Email(s):")
            .with_help_message("Enter an email address, or press ESC to leave empty. Comma-separate multiple addresses")
            .with_placeholder("email@example.com,another-address@example.org")
            .with_validator(|input: &str| Ok(input.split(",").map(|address| {
                // Lax email validation. The CA may apply stricter requirements.
                let address = address.trim();
                if address.is_empty() {
                    // Empty addresses are valid, but skipped
                    return Validation::Valid;
                }
                let parts = address.split('@').collect::<Vec<_>>();
                if parts.len() != 2 {
                    return Validation::Invalid((address.to_string() + " does not look like an email address").into());
                }
                if !parts[1].contains(".") {
                    return Validation::Invalid((address.to_string() + " does not look like an email address").into());
                }
                // There are still lots of possible invalid addresses here, but we don't know exactly
                // what the CA will accept anyway.
                Validation::Valid
            }).find(|validation| matches!(validation, Validation::Invalid(_))).unwrap_or(Validation::Valid)));
        let email_string = email_prompt
            .prompt_skippable()
            .context("No answer to email dialog")?
            .unwrap_or("".to_string());
        let emails = email_string
            .split(",")
            .map(|email| email.trim())
            .filter(|email| !email.is_empty())
            .map(|email| "mailto:".to_owned() + email)
            .collect::<Vec<_>>();
        let mut contacts = Vec::with_capacity(emails.len());
        for contact in emails {
            contacts.push(Url::try_from(contact.as_str()).context("Validating contact URL")?);
        }
        let ca_name = &ca.name;
        let ca_id = &ca.identifier;
        let account_num = ca.accounts.len();
        let account_name = if account_num > 0 {
            format!("{ca_name} ({account_num})")
        } else {
            ca_name.to_string()
        };
        let account_id = format!("{ca_id}@{account_num}");
        Certonaut::create_account(
            &acme_client,
            NewAccountOptions {
                name: account_name,
                identifier: account_id,
                contacts,
                key_type: KeyType::Ecdsa(Curve::P256),
                terms_of_service_agreed: tos_status,
            },
        )
        .await
    }
}
