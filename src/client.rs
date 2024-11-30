use crate::rpc::client::RpcClient;
use crate::rpc::service::{Account, CertificateAuthority};
use crate::CRATE_NAME;
use anyhow::{Context, Error};
use crossterm::style::Stylize;
use inquire::Select;
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

    pub async fn interactive_issuance(&mut self) -> Result<(), anyhow::Error> {
        println!(
            "{}",
            format!("{CRATE_NAME} guided certificate issuance")
                .green()
                .on_black()
        );
        let ca = loop {
            match self.user_select_ca().await? {
                CaChoice::NewCa => {
                    self.user_create_ca().await?;
                }
                CaChoice::ExistingCa(ca) => {
                    break ca;
                }
            }
        };
        let account = loop {
            match self.user_select_account(&ca).await? {
                AccountChoice::NewAccount => {
                    self.user_create_account(&ca).await?;
                }
                AccountChoice::ExistingAccount(ac) => {
                    break ac;
                }
            }
        };
        println!("Selected account {account:#?} for CA {ca:#?}");
        Ok(())
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
        let default_ca = configured_ca
            .iter()
            .enumerate()
            .find(|(_, ca)| ca.is_default)
            .map(|(idx, ca)| (idx, { CaChoice::ExistingCa(ca.clone()) }));
        let choices = configured_ca
            .into_iter()
            .map(|ca| CaChoice::ExistingCa(ca))
            .collect::<Vec<_>>();
        let mut ca_choice =
            Select::new("Select the Certificate Authority you want to use", choices);
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
        todo!("Create account logic")
    }
}

#[derive(Debug)]
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
            CaChoice::NewCa => write!(f, "Add new")?,
        }
        Ok(())
    }
}

#[derive(Debug)]
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
            AccountChoice::NewAccount => write!(f, "Add new")?,
        }
        Ok(())
    }
}
