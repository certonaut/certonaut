use crate::cli::{CertificateModifyCommand, IssueCommand};
use crate::config::{
    AdvancedCertificateConfiguration, CertificateConfiguration, ConfigBackend,
    InstallerConfiguration,
};
use crate::Certonaut;
use crate::CRATE_NAME;
use anyhow::{bail, Context, Error};

pub struct NonInteractiveService<CB> {
    client: Certonaut<CB>,
}

impl<CB: ConfigBackend> NonInteractiveService<CB> {
    pub fn new(client: Certonaut<CB>) -> Self {
        Self { client }
    }

    pub async fn noninteractive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!("{CRATE_NAME} non-interactive certificate issuance");
        let config = self.build_cert_config(issue_cmd)?;
        self.client.issue_new(config).await
    }

    pub fn modify_cert_config(&mut self, cmd: CertificateModifyCommand) -> Result<(), Error> {
        let cert_id = cmd
            .cert_id
            .context("A certificate ID must be specified in non-interactive mode")?;
        let current_config = self
            .client
            .get_certificate(&cert_id)
            .cloned()
            .context(format!("Certificate {cert_id} not found"))?;
        let new_config = crate::modify_certificate_config(current_config, cmd.new_config)?;
        self.client.replace_certificate(&cert_id, new_config)?;
        println!(
            "Successfully modified certificate configuration. The new configuration will become effective on the next renewal."
        );
        Ok(())
    }

    fn build_cert_config(
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
                let accounts = &issuer.accounts;
                if let Some(account) = accounts.values().next() {
                    if accounts.len() == 1 {
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
            crate::domain_solver_maps_from_command_line(issue_cmd.solver_configuration)?;
        let domains = domains_and_solvers.domains;
        if domains.is_empty() {
            bail!(
                "In non-interactive mode you must specify both domains and solvers on the command line"
            );
        }
        let solvers = domains_and_solvers.solvers;
        let cert_name = if let Some(cert_name) = &issue_cmd.cert_name {
            cert_name.to_string()
        } else {
            self.client.choose_cert_name_from_domains(domains.keys())
        };
        Ok(CertificateConfiguration {
            display_name: cert_name,
            auto_renew: true,
            ca_identifier: ca,
            account_identifier: account,
            key_type: issue_cmd.advanced.key_type.unwrap_or_default().into(),
            domains,
            solvers,
            advanced: AdvancedCertificateConfiguration {
                reuse_key: issue_cmd.advanced.reuse_key,
                lifetime_seconds: issue_cmd
                    .advanced
                    .lifetime
                    .map(|lifetime| lifetime.as_secs()),
                profile: issue_cmd.advanced.profile,
            },
            installer: issue_cmd
                .install_script
                .map(|script| InstallerConfiguration::Script { script }),
        })
    }
}
