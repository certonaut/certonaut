use crate::CRATE_NAME;
use crate::cli::{
    AccountCreateCommand, AccountDeleteCommand, AccountImportCommand, CertificateModifyCommand,
    DebugCommonArgs, DebugDeactivateAuthorizationCommand, DebugShowAuthorizationCommand,
    DebugShowChallengeCommand, DebugShowOrderCommand, IssueCommand, IssuerAddCommand,
    IssuerRemoveCommand, RevokeCommand,
};
use crate::config::{
    AdvancedCertificateConfiguration, CertificateAuthorityConfiguration, CertificateConfiguration,
    ConfigBackend, InstallerConfiguration,
};
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::crypto::jws::ExternalAccountBinding;
use crate::issuer::AcmeIssuerWithAccount;
use crate::{Certonaut, NewAccountOptions};
use anyhow::{Context, Error, bail};
use crossterm::style::Stylize;
use std::str::FromStr;
use tracing::warn;
use url::Url;

pub struct NonInteractiveService<CB> {
    client: Certonaut<CB>,
}

impl<CB: ConfigBackend> NonInteractiveService<CB> {
    pub fn new(client: Certonaut<CB>) -> Self {
        Self { client }
    }

    pub async fn noninteractive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!("{CRATE_NAME} non-interactive certificate issuance");
        let config = self.build_cert_config(issue_cmd).await?;
        self.client.issue_new(config).await
    }

    pub async fn modify_cert_config(&mut self, cmd: CertificateModifyCommand) -> Result<(), Error> {
        let cert_id = cmd
            .cert_id
            .context("A certificate ID must be specified in non-interactive mode")?;
        let current_config = self
            .client
            .get_certificate(&cert_id)
            .cloned()
            .context(format!("Certificate {cert_id} not found"))?;
        let new_config = crate::modify_certificate_config(current_config, cmd.new_config).await?;
        self.client.replace_certificate(&cert_id, new_config)?;
        println!(
            "Successfully modified certificate configuration. The new configuration will become effective on the next renewal."
        );
        Ok(())
    }

    pub async fn create_account(&mut self, cmd: AccountCreateCommand) -> Result<(), Error> {
        let Some(ca_id) = cmd.ca_identifier else {
            bail!("A certificate authority must be specified in noninteractive mode")
        };
        let issuer = self.client.get_ca(&ca_id).context("CA not found")?;
        let ca_name = issuer.config.name.as_str().green();
        let mut contacts = Vec::new();
        for contact in cmd.contact {
            contacts.push(
                Url::from_str(&("mailto:".to_owned() + &contact))
                    .context(format!("Parsing mail address {contact}"))?,
            );
        }
        println!("Creating a new account at CA {ca_name}");
        let acme_client = issuer.client().await?;
        let ca_name = &issuer.config.name;
        let account_num = issuer.num_accounts();
        let account_name = cmd.account_name.unwrap_or_else(|| {
            if account_num > 0 {
                format!("{ca_name} ({account_num})")
            } else {
                ca_name.to_string()
            }
        });
        let account_id = cmd
            .account_id
            .unwrap_or_else(|| format!("{ca_id}@{account_num}"));
        let eab = if let Some(kid) = cmd.external_account_kid {
            if let Some(hmac_base64) = cmd.external_account_hmac_key {
                Some(ExternalAccountBinding::try_new(kid, hmac_base64)?)
            } else {
                None
            }
        } else {
            None
        };
        let new_account = Certonaut::<CB>::create_account(
            acme_client,
            NewAccountOptions {
                name: account_name,
                identifier: account_id,
                contacts,
                key_type: KeyType::Ecdsa(Curve::P256),
                terms_of_service_agreed: Some(cmd.terms_of_service_agreed),
                external_account_binding: eab,
            },
        )
        .await?;
        let acc_id = new_account.config.identifier.clone();
        self.client.add_new_account(&ca_id, new_account)?;
        let account = self.client.get_issuer_with_account(&ca_id, &acc_id)?;
        Certonaut::<CB>::print_account(&account).await;
        println!("Successfully added new account");
        Ok(())
    }

    pub async fn import_account(&mut self, cmd: AccountImportCommand) -> Result<(), Error> {
        let Some(ca_id) = cmd.ca_identifier else {
            bail!("A certificate authority must be specified in noninteractive mode")
        };
        let Some(account_id) = cmd.account_id else {
            bail!("An account ID in noninteractive mode")
        };
        let account_name = cmd.account_name.unwrap_or_else(|| account_id.clone());
        let Some(key_path) = cmd.key_file else {
            bail!("A path to the account key file must be specified in noninteractive mode")
        };
        let key_file = std::fs::File::open(key_path).context("Failed to open account key file")?;
        let account_key = crate::crypto::asymmetric::KeyPair::load_from_disk(key_file)
            .context("Failed to load account key file. Make sure it is in PEM format.")?;
        let imported_account = self
            .client
            .import_account(&ca_id, &account_id, &account_name, account_key)
            .await?;
        self.client.add_new_account(&ca_id, imported_account)?;
        Ok(())
    }

    pub async fn delete_account(&mut self, cmd: AccountDeleteCommand) -> Result<(), Error> {
        let Some(ca_id) = cmd.ca_identifier else {
            bail!("A certificate authority must be specified in noninteractive mode")
        };
        let issuer = self.client.get_ca(&ca_id).context("CA not found")?;
        let Some(account_id) = cmd.account_id else {
            bail!("An account ID must be specified in noninteractive mode")
        };
        let issuer = issuer
            .with_account(&account_id)
            .context(format!("Account {account_id} not found at CA {ca_id}"))?;
        if let Err(e) = issuer.deactivate_account().await {
            warn!("Account deactivation at CA failed: {e:#}");
        } else {
            println!("Account deactivated.");
        }
        self.client.remove_account(&ca_id, &account_id)?;
        println!("Successfully removed account from configuration");
        Ok(())
    }

    pub async fn add_new_ca(&mut self, cmd: IssuerAddCommand) -> Result<(), Error> {
        let Some(name) = cmd.name else {
            bail!("CA must be given a name on the command line in noninteractive mode");
        };
        let identifier = cmd
            .id
            .unwrap_or_else(|| self.client.choose_ca_id_from_name(&name));
        let Some(acme_directory) = cmd.acme_directory else {
            bail!("ACME directory URL must be specified in noninteractive mode");
        };
        let config = CertificateAuthorityConfiguration {
            name,
            identifier: identifier.clone(),
            acme_directory,
            public: cmd.public,
            testing: cmd.testing,
            default: cmd.default,
            trusted_roots: vec![],
        };
        self.client.add_new_ca(config)?;
        let new_issuer = self
            .client
            .get_ca(&identifier)
            .context("BUG: Freshly created CA not found")?;
        Certonaut::<CB>::print_issuer(new_issuer).await;
        Ok(())
    }

    pub fn remove_ca(&mut self, cmd: IssuerRemoveCommand) -> Result<(), Error> {
        let Some(ca_id) = cmd.id else {
            bail!("A CA identifier must be specified in non-interactive mode");
        };
        self.client.remove_ca(&ca_id)?;
        println!("Successfully removed CA {ca_id} from configuration");
        Ok(())
    }

    async fn build_cert_config(
        &mut self,
        issue_cmd: IssueCommand,
    ) -> Result<CertificateConfiguration, Error> {
        let ca = issue_cmd
            .ca
            .or_else(|| {
                self.client
                    .get_default_ca()
                    .map(|issuer| issuer.config.identifier.clone())
            })
            .context("No default Certificate Authority found. Specify a CA on the command line for non-interactive mode")?;
        let issuer = self
            .client
            .get_ca(&ca)
            .context(format!("CA {ca} not found"))?;
        let account = issue_cmd
            .account
            .or_else(|| {
                let mut accounts = issuer.get_accounts();
                if let Some(account) = accounts.next() {
                    if issuer.num_accounts() == 1 {
                        Some(account.config.identifier.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .context(format!("You must specify an account for CA {ca}"))?;
        let domains_and_solvers =
            crate::domain_solver_maps_from_command_line(issue_cmd.solver_configuration).await?;
        if domains_and_solvers.domains.is_empty() {
            bail!(
                "In non-interactive mode you must specify both domains and solvers on the command line"
            );
        }
        let cert_name = if let Some(cert_name) = &issue_cmd.cert_name {
            cert_name.to_string()
        } else {
            self.client
                .choose_cert_name_from_domains(domains_and_solvers.domains.keys())
        };
        issuer
            .validate_profile(issue_cmd.advanced.profile.as_ref())
            .await?;
        Ok(CertificateConfiguration {
            display_name: cert_name,
            auto_renew: true,
            ca_identifier: ca,
            account_identifier: account,
            key_type: issue_cmd.advanced.key_type.unwrap_or_default().into(),
            domains_and_solvers,
            advanced: AdvancedCertificateConfiguration {
                reuse_key: issue_cmd.advanced.reuse_key,
                lifetime_seconds: issue_cmd
                    .advanced
                    .lifetime
                    .map(|lifetime| lifetime.as_secs()),
                profile: issue_cmd.advanced.profile,
                alternate_chain: issue_cmd.advanced.preferred_chain,
            },
            installer: issue_cmd
                .install_script
                .map(|script| InstallerConfiguration::Script { script }),
        })
    }

    pub async fn revoke_certificate(&self, revoke_cmd: RevokeCommand) -> anyhow::Result<()> {
        let cert_id = revoke_cmd
            .cert_id
            .context("A certificate ID to revoke must be specified in non-interactive mode")?;
        let reason = revoke_cmd.reason;
        self.client
            .revoke_certificate(&cert_id, reason)
            .await
            .context("Failed to revoke certificate")
    }

    pub async fn debug_show_order(&self, cmd: DebugShowOrderCommand) -> anyhow::Result<()> {
        let issuer = self.debug_get_issuer(&cmd.common)?;
        let order = issuer.get_order(&cmd.order_url).await?;
        println!("{order:#?}");
        Ok(())
    }

    pub async fn debug_show_authorization(
        &self,
        cmd: DebugShowAuthorizationCommand,
    ) -> anyhow::Result<()> {
        let issuer = self.debug_get_issuer(&cmd.common)?;
        let authorization = issuer.get_authorization(&cmd.authorization_url).await?;
        println!("{authorization:#?}");
        Ok(())
    }

    pub async fn debug_show_challenge(&self, cmd: DebugShowChallengeCommand) -> anyhow::Result<()> {
        let issuer = self.debug_get_issuer(&cmd.common)?;
        let challenge = issuer.get_challenge(&cmd.challenge_url).await?;
        println!("{challenge:#?}");
        Ok(())
    }

    pub async fn debug_deactivate_authorization(
        &self,
        cmd: DebugDeactivateAuthorizationCommand,
    ) -> anyhow::Result<()> {
        let issuer = self.debug_get_issuer(&cmd.common)?;
        issuer.deactivate_authorizations(&cmd.order_url).await?;
        println!(
            "Successfully deactivated authorizations for order {}",
            cmd.order_url
        );
        Ok(())
    }

    fn debug_get_issuer(
        &'_ self,
        debug: &DebugCommonArgs,
    ) -> anyhow::Result<AcmeIssuerWithAccount<'_>> {
        Ok(if let Some(account_id) = &debug.account {
            self.client.get_issuer_with_account(&debug.ca, account_id)?
        } else {
            let ca = self
                .client
                .get_ca(&debug.ca)
                .context(format!("CA {} not found", debug.ca))?;
            if ca.num_accounts() == 0 {
                bail!("No Accounts found for CA {}", ca.config.identifier);
            }
            if ca.num_accounts() > 1 {
                bail!(
                    "Multiple accounts found for CA {}. Specify an account explicitly on the command line",
                    ca.config.identifier
                );
            }
            let single_account = ca
                .get_accounts()
                .map(|account| &account.get_config().identifier)
                .next()
                .unwrap();
            ca.with_account(single_account)
                .context("Account not found")?
        })
    }
}
