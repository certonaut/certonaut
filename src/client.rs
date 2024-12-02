use crate::rpc::client::RpcClient;
use crate::rpc::service::{Account, CertificateAuthority};
use crate::{IssueCommand, CRATE_NAME};
use anyhow::{bail, Context, Error};
use crossterm::style::Stylize;
use inquire::validator::Validation;
use inquire::{Confirm, InquireError, Select, Text};
use std::fmt::Display;
use tonic::transport::Channel;

#[derive(Debug)]
pub struct Rover {
    rpc: RpcClient<Channel>,
}

impl Rover {
    pub fn new(rpc: RpcClient<Channel>) -> Self {
        Self { rpc }
    }

    async fn find_ca_by_id(&mut self, id: &str) -> Result<Option<CertificateAuthority>, Error> {
        Ok(self
            .rpc
            .list_certificate_authorities()
            .await?
            .into_iter()
            .find(|ca| ca.id == *id))
    }

    async fn find_account_by_id(
        &mut self,
        ca: &CertificateAuthority,
        id: &str,
    ) -> Result<Option<Account>, Error> {
        Ok(self
            .rpc
            .list_accounts(ca.id.clone())
            .await?
            .into_iter()
            .find(|acc| acc.id == *id))
    }

    pub async fn interactive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!(
            "{}",
            format!("{CRATE_NAME} guided certificate issuance")
                .green()
                .on_black()
        );
        let (account, ca) = self.user_select_ca_account(&issue_cmd).await?;
        println!("Selected account {account:#?} for CA {ca:#?}");
        Ok(())
    }

    async fn user_select_ca_account(
        &mut self,
        issue_cmd: &IssueCommand,
    ) -> Result<(CertificateAuthority, Account), Error> {
        let ca = if let Some(ca_id) = &issue_cmd.ca {
            self.find_ca_by_id(ca_id)
                .await?
                .ok_or(anyhow::anyhow!("CA {ca_id} not found"))?
        } else {
            loop {
                match self.user_select_ca().await? {
                    CaChoice::NewCa => {
                        self.user_create_ca().await?;
                    }
                    CaChoice::ExistingCa(ca) => {
                        break ca;
                    }
                }
            }
        };
        let account = if let Some(account_id) = &issue_cmd.account {
            self.find_account_by_id(&ca, account_id)
                .await?
                .ok_or(anyhow::anyhow!("Account {account_id} not found"))?
        } else {
            loop {
                match self.user_select_account(&ca).await? {
                    AccountChoice::NewAccount => {
                        self.user_create_account(&ca).await?;
                    }
                    AccountChoice::ExistingAccount(ac) => {
                        break ac;
                    }
                }
            }
        };
        Ok((ca, account))
    }

    async fn user_select_ca(&mut self) -> Result<CaChoice, Error> {
        let configured_ca = self
            .rpc
            .list_certificate_authorities()
            .await
            .context("failed to list certificate authorities")?;
        if configured_ca.is_empty() {
            return Ok(CaChoice::NewCa);
        }
        let mut choices = configured_ca
            .into_iter()
            .map(CaChoice::ExistingCa)
            .collect::<Vec<_>>();
        // TODO: Sort by some preference order instead?
        choices.sort_by_key(|a| a.to_string());
        choices.push(CaChoice::NewCa);
        let default_ca = choices
            .iter()
            .enumerate()
            .find(|(_, ca)| match ca {
                CaChoice::ExistingCa(ca) => ca.is_default,
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

    async fn user_create_ca(&mut self) -> Result<(), Error> {
        todo!("Create CA logic")
    }

    async fn user_select_account(
        &mut self,
        ca: &CertificateAuthority,
    ) -> Result<AccountChoice, Error> {
        let configured_accounts = self.rpc.list_accounts(ca.id.clone()).await?;
        if configured_accounts.is_empty() {
            return Ok(AccountChoice::NewAccount);
        }
        todo!()
    }

    async fn user_create_account(&mut self, ca: &CertificateAuthority) -> Result<(), Error> {
        let ca_name = ca.name.as_str().green().on_black();
        let mut tos_status = None;
        if let Some(meta) = &ca.metadata {
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
            .with_default("")
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
                if parts[1].contains(".") {
                    return Validation::Invalid((address.to_string() + " does not look like an email address").into());
                }
                // There are still lots of possible invalid addresses here, but we don't know exactly
                // what the CA will accept anyway.
                Validation::Valid
            }).find(|validation| matches!(validation, Validation::Invalid(_))).unwrap_or(Validation::Valid)));
        let email_string = email_prompt
            .prompt()
            .or_else(|result| {
                if matches!(result, InquireError::OperationCanceled) {
                    Ok("".to_string())
                } else {
                    Err(result)
                }
            })
            .context("No answer to email dialog")?;
        let emails = email_string
            .split(",")
            .map(|email| email.trim())
            .filter(|email| !email.is_empty())
            .map(|email| "mailto:".to_owned() + email)
            .collect::<Vec<_>>();
        let account = self
            .rpc
            .create_account(ca.id.clone(), "".to_string(), emails, tos_status, None)
            .await?;
        println!("Success!!!");
        println!("{account:?}");
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum CaChoice {
    ExistingCa(CertificateAuthority),
    NewCa,
}

impl PartialEq for CaChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => {
                self_ca.id == other_ca.id
            }
            _ => false,
        }
    }
}

impl Display for CaChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaChoice::ExistingCa(ca) => {
                let name = &ca.name;
                write!(f, "{name}")?;
                if ca.is_testing {
                    write!(f, " (Testing)")?
                };
            }
            CaChoice::NewCa => write!(f, "Add new CA")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum AccountChoice {
    ExistingAccount(Account),
    NewAccount,
}

impl PartialEq for AccountChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                AccountChoice::ExistingAccount(self_acc),
                AccountChoice::ExistingAccount(other_acc),
            ) => self_acc.id == other_acc.id,
            _ => false,
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
