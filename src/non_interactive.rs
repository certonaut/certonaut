use crate::cli::IssueCommand;
use crate::config::{AdvancedCertificateConfiguration, CertificateConfiguration, ConfigBackend};
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
        let mut solver_configs = Vec::with_capacity(issue_cmd.solver_configuration.len());
        for solver_config in issue_cmd.solver_configuration {
            solver_configs.push(
                solver_config
                    .solver
                    .build_from_command_line(solver_config)?,
            );
        }
        let domains_and_solvers = crate::build_domain_solver_maps(solver_configs)?;
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
            domains: domains
                .into_iter()
                .map(|(id, solver)| (id.to_string(), solver))
                .collect(),
            solvers,
            advanced: AdvancedCertificateConfiguration {
                reuse_key: issue_cmd.advanced.reuse_key,
                lifetime_seconds: issue_cmd
                    .advanced
                    .lifetime
                    .map(|lifetime| lifetime.as_secs()),
                profile: issue_cmd.advanced.profile,
            },
        })
    }
}
