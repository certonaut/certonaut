use crate::challenge_solver::CHALLENGE_SOLVER_REGISTRY;
use crate::cli::{CertificateModifyCommand, CommandLineKeyType, IssueCommand};
use crate::config::{
    AccountConfiguration, AdvancedCertificateConfiguration, CertificateAuthorityConfiguration,
    CertificateConfiguration, ConfigBackend, InstallerConfiguration,
};
use crate::crypto::asymmetric::{Curve, KeyType};
use crate::interactive::editor::{ClosureEditor, InteractiveConfigEditor};
use crate::time::{ParsedDuration, humanize_duration};
use crate::{
    AcmeAccount, AcmeIssuer, AcmeIssuerWithAccount, AcmeProfile, CRATE_NAME, Certonaut,
    DomainSolverMap, Identifier, NewAccountOptions, choose_solver_name,
};
use anyhow::{Context, Error, anyhow, bail};
use crossterm::style::Stylize;
use futures::FutureExt;
use inquire::validator::Validation;
use inquire::{Confirm, CustomType, Select, Text};
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Mutex;
use strum::VariantArray;
use tokio::sync::RwLock;
use tracing::warn;
use url::Url;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct InteractiveService<CB> {
    client: Certonaut<CB>,
}

impl<CB: ConfigBackend + Send + Sync> InteractiveService<CB> {
    pub fn new(client: Certonaut<CB>) -> Self {
        Self { client }
    }

    pub async fn interactive_issuance(&mut self, issue_cmd: IssueCommand) -> Result<(), Error> {
        println!(
            "{}",
            format!("{CRATE_NAME} interactive certificate issuance").green()
        );
        let (initial_issuer, initial_account) = self.user_select_ca_and_account(&issue_cmd).await?;
        // TODO: Detect if we already have this exact set of domains, or a subset of it and offer options depending on that.
        let initial_domains = Self::user_ask_initial_cert_domains(&issue_cmd)?;
        let domain_solver_map = Self::user_ask_initial_solvers(&issue_cmd, initial_domains).await?;
        let cert_name = if let Some(cert_name) = &issue_cmd.cert_name {
            cert_name.to_string()
        } else {
            self.client
                .choose_cert_name_from_domains(domain_solver_map.domains.keys())
        };
        let issuer = self
            .client
            .get_ca(&initial_issuer)
            .context(format!("CA {initial_issuer} not found"))?;
        issuer
            .validate_profile(issue_cmd.advanced.profile.as_ref())
            .await?;
        let initial_config = CertificateConfiguration {
            display_name: cert_name,
            auto_renew: true,
            ca_identifier: initial_issuer,
            account_identifier: initial_account,
            key_type: issue_cmd.advanced.key_type.unwrap_or_default().into(),
            domains_and_solvers: domain_solver_map,
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
        };
        let cert_config = self
            .interactive_edit_cert_configuration(initial_config)
            .await?;
        self.client.issue_new(cert_config).await
    }

    pub async fn interactive_add_ca(&mut self) -> Result<(), Error> {
        let new_ca = Self::user_create_ca(&mut self.client)?;
        let ca_id = new_ca.identifier.clone();
        self.client.add_new_ca(new_ca)?;
        let issuer = self
            .client
            .get_ca(&ca_id)
            .ok_or(anyhow!("Freshly created CA not found"))?;
        Certonaut::<CB>::print_issuer(issuer).await;
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
        Certonaut::<CB>::print_account(&account).await;
        println!("Successfully added new account");
        Ok(())
    }

    pub async fn interactive_remove_ca(&mut self) -> Result<(), Error> {
        let ca_id = self.interactive_select_ca(false)?;
        let issuer = self.client.get_ca(&ca_id).ok_or(anyhow!("CA not found"))?;
        println!("You have selected this CA for deletion:");
        Certonaut::<CB>::print_issuer(issuer).await;
        let delete = Confirm::new("Are you sure you want to remove this CA from configuration?")
            .with_default(false)
            .prompt()
            .context("No answer to deletion prompt")?;
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
        println!(
            "You have selected the following account for {}",
            "deletion".red()
        );
        Certonaut::<CB>::print_account(&account).await;
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

    pub async fn interactive_modify_cert_configuration(
        &mut self,
        cmd: CertificateModifyCommand,
    ) -> Result<(), Error> {
        let cert_id = match cmd.cert_id {
            Some(cert_id) => cert_id,
            None => self.user_select_cert()?,
        };
        let current_cert_config = self
            .client
            .get_certificate(&cert_id)
            .cloned()
            .context(format!("Certificate {cert_id} not found"))?;
        let merged_config =
            crate::modify_certificate_config(current_cert_config, cmd.new_config).await?;

        let new_config = self
            .interactive_edit_cert_configuration(merged_config)
            .await?;
        self.client.replace_certificate(&cert_id, new_config)?;
        println!(
            "Successfully modified certificate configuration. The new configuration will become effective on the next renewal."
        );
        Ok(())
    }

    fn user_select_cert(&self) -> Result<String, Error> {
        let certs: Vec<_> = self
            .client
            .certificates
            .iter()
            .map(|(cert_id, cert_config)| CertChoice {
                id: cert_id.to_string(),
                display_name: cert_config.display_name.to_string(),
                domains: cert_config
                    .domains_and_solvers
                    .domains
                    .keys()
                    .sorted()
                    .map(std::string::ToString::to_string)
                    .collect(),
            })
            .collect();
        if certs.is_empty() {
            bail!("No certificates found");
        }
        let choice = Select::new("Select a certificate", certs)
            .prompt()
            .context("No certificate selected")?;
        Ok(choice.id)
    }

    async fn interactive_edit_cert_configuration(
        &mut self,
        config: CertificateConfiguration,
    ) -> Result<CertificateConfiguration, Error> {
        let self_locked = RwLock::new(self);
        let ca_display_updater = async |config: &CertificateConfiguration| {
            let lock = self_locked.read().await;
            match lock.client.get_ca(&config.ca_identifier) {
                None => "CA not found".into(),
                Some(ca) => {
                    let ca_name = ca.config.name.clone();
                    if ca.num_accounts() > 1 {
                        let account_name = match ca.get_account(&config.account_identifier) {
                            None => "Account not found",
                            Some(account) => &account.config.name,
                        };
                        format!("{ca_name} ({account_name})")
                    } else {
                        ca_name
                    }
                }
            }
        };
        let ca_display: Mutex<String> = Mutex::new(ca_display_updater(&config).await);
        println!("{}", "Certificate Configuration:".dark_green());
        println!("Select an option to view or edit");
        let final_config = InteractiveConfigEditor::new(
            "Select an option to change it",
            config,
            Self::cert_edit_basic_editors(&self_locked)
                .chain(
                    [ClosureEditor::new(
                        "Certificate Authority",
                        |_config: &CertificateConfiguration| {
                            ca_display.lock().unwrap().clone().into()
                        },
                        |mut config: CertificateConfiguration| {
                            async {
                                let mut lock = self_locked.write().await;
                                let (ca, account) = lock
                                    .user_select_ca_and_account(&IssueCommand::default())
                                    .await?;
                                config.ca_identifier = ca;
                                config.account_identifier = account;
                                drop(lock);
                                let new_ca_display = ca_display_updater(&config).await;
                                let mut ca_display = ca_display.lock().unwrap();
                                *ca_display = new_ca_display;
                                Ok(config)
                            }
                            .boxed()
                        },
                    )]
                    .into_iter(),
                )
                .chain(Self::cert_edit_advanced_editors(&self_locked)),
            |_c| async { Ok(true) }.boxed(),
        )
        .edit_config()
        .await?;
        Ok(final_config)
    }

    fn cert_edit_basic_editors<'a>(
        self_locked: &'a RwLock<&'a mut Self>,
    ) -> impl Iterator<Item = ClosureEditor<'a, CertificateConfiguration>> {
        [
            ClosureEditor::new(
                "Domains",
                |config: &CertificateConfiguration| {
                    config
                        .domains_and_solvers
                        .domains
                        .keys()
                        .sorted()
                        .join(", ")
                        .into()
                },
                |mut config: CertificateConfiguration| {
                    async {
                        let sorted_domains: Vec<_> = config
                            .domains_and_solvers
                            .domains
                            .keys()
                            .cloned()
                            .sorted()
                            .collect();
                        let new_domains = Self::user_ask_cert_domains(sorted_domains.iter())?;
                        if new_domains.iter().sorted().eq(sorted_domains.iter()) {
                            // No change
                            return Ok(config);
                        }
                        let lock = self_locked.read().await;
                        let cert_name = lock
                            .client
                            .choose_cert_name_from_domains(new_domains.iter());
                        config.display_name = cert_name;
                        let mut old_domains = config.domains_and_solvers.domains;
                        let new_domains: HashMap<_, _> = new_domains
                            .into_iter()
                            .map(|identifier| {
                                let solver_name =
                                    old_domains.remove(&identifier).unwrap_or_default();
                                (identifier, solver_name)
                            })
                            .collect();
                        config.domains_and_solvers.domains = new_domains;
                        // Check if there is any new identifier that needs a solver
                        if config
                            .domains_and_solvers
                            .domains
                            .values()
                            .any(String::is_empty)
                        {
                            config.domains_and_solvers =
                                Self::user_ask_solvers(config.domains_and_solvers).await?;
                        }
                        Self::remove_unused_solvers(&mut config.domains_and_solvers);
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Solvers",
                |config: &CertificateConfiguration| {
                    config
                        .domains_and_solvers
                        .solvers
                        .keys()
                        .sorted()
                        .map(|solver| {
                            let domains = config
                                .domains_and_solvers
                                .domains
                                .iter()
                                .filter_map(|(candidate_domain, candidate_solver)| {
                                    if solver == candidate_solver {
                                        Some(candidate_domain)
                                    } else {
                                        None
                                    }
                                })
                                .sorted()
                                .join(", ");
                            format!("{solver} ({domains})")
                        })
                        .join(", ")
                        .into()
                },
                |mut config: CertificateConfiguration| {
                    async {
                        config.domains_and_solvers =
                            Self::user_ask_solvers(config.domains_and_solvers).await?;
                        Self::remove_unused_solvers(&mut config.domains_and_solvers);
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Name",
                |config: &CertificateConfiguration| (&config.display_name).into(),
                |mut config: CertificateConfiguration| {
                    async {
                        config.display_name = Self::user_ask_cert_name(config.display_name)?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
        ]
        .into_iter()
    }

    fn remove_unused_solvers(map: &mut DomainSolverMap) {
        let required_solvers: HashSet<_> = map.domains.values().collect();
        map.solvers
            .retain(|name, _| required_solvers.contains(name));
    }

    fn cert_edit_advanced_editors<'a>(
        self_locked: &'a RwLock<&'a mut Self>,
    ) -> impl Iterator<Item = ClosureEditor<'a, CertificateConfiguration>> {
        [
            ClosureEditor::new(
                "Key Type",
                |config: &CertificateConfiguration| config.key_type.to_string().into(),
                |mut config| {
                    async {
                        config.key_type = Self::user_ask_key_type(config.key_type)?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Advanced",
                |_config: &CertificateConfiguration| "View/Change advanced options".into(),
                |mut config| {
                    async {
                        let ca_identifier = config.ca_identifier.clone();
                        let account_identifier = config.account_identifier.clone();
                        let new_advanced = InteractiveConfigEditor::new(
                            "Select an option",
                            config.advanced,
                            Self::cert_edit_advanced_inner_editors(
                                ca_identifier,
                                account_identifier,
                                self_locked,
                            ),
                            |_config| async { Ok(true) }.boxed(),
                        )
                        .edit_config()
                        .await?;
                        config.advanced = new_advanced;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Install Script",
                |config: &CertificateConfiguration| match &config.installer {
                    Some(InstallerConfiguration::Script { script }) => script.into(),
                    None => "Nothing".into(),
                },
                |mut config| {
                    async {
                        config.installer = Self::user_ask_installer(config.installer)?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
        ]
        .into_iter()
    }

    fn cert_edit_advanced_inner_editors<'a>(
        ca: String,
        account: String,
        self_locked: &'a RwLock<&'a mut Self>,
    ) -> impl Iterator<Item = ClosureEditor<'a, AdvancedCertificateConfiguration>> {
        [
            ClosureEditor::new(
                "Requested Lifetime",
                |config: &AdvancedCertificateConfiguration| match config.lifetime_seconds {
                    None => "Not specified".into(),
                    Some(lifetime) => {
                        // TODO: This can overflow, but do we really care?
                        humanize_duration(time::Duration::seconds(lifetime as i64)).into()
                    }
                },
                |mut config| {
                    async {
                        config.lifetime_seconds =
                            Self::user_ask_cert_lifetime(config.lifetime_seconds)?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Profile",
                |config: &AdvancedCertificateConfiguration| {
                    config.profile.as_deref().unwrap_or("Not specified").into()
                },
                move |mut config| {
                    let ca = ca.clone();
                    let account = account.clone();
                    async move {
                        let lock = self_locked.read().await;
                        let issuer = lock.client.get_issuer_with_account(&ca, &account)?;
                        config.profile =
                            Self::user_ask_cert_profile(&issuer, config.profile).await?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
            ClosureEditor::new(
                "Reuse Key",
                |config: &AdvancedCertificateConfiguration| {
                    if config.reuse_key { "yes" } else { "no" }.into()
                },
                |mut config| {
                    async {
                        config.reuse_key = Self::user_ask_key_reuse(config.reuse_key)?;
                        Ok(config)
                    }
                    .boxed()
                },
            ),
        ]
        .into_iter()
    }

    async fn user_ask_initial_solvers(
        issue_cmd: &IssueCommand,
        domains: HashSet<Identifier>,
    ) -> Result<DomainSolverMap, Error> {
        if issue_cmd.solver_configuration.is_empty() {
            let initial_map = DomainSolverMap {
                domains: domains
                    .into_iter()
                    .map(|domain| (domain, String::new()))
                    .collect(),
                solvers: HashMap::new(),
            };
            Self::user_ask_solvers(initial_map).await
        } else {
            crate::domain_solver_maps_from_command_line(issue_cmd.solver_configuration.clone())
                .await
        }
    }

    async fn user_ask_solvers(solver_map: DomainSolverMap) -> Result<DomainSolverMap, Error> {
        println!("{}", "To issue a certificate, most CA's require you to prove control over all identifiers included in the certificate.
There are several ways to do this, and the best method depends on your system and preferences.
You need to provide challenge \"solvers\" to authenticate the requested identifiers.".blue());
        let identifier_editors = solver_map
            .domains
            .keys()
            .cloned()
            .sorted()
            .map(|identifier| {
                let get_identifier = identifier.clone();
                ClosureEditor::new(
                    identifier.clone(),
                    move |map: &DomainSolverMap| {
                        let solver = map
                            .domains
                            .get(&get_identifier)
                            .map_or("N/A", |s| s.as_str());
                        if solver.is_empty() {
                            "N/A".into()
                        } else {
                            solver.into()
                        }
                    },
                    move |map| {
                        let identifier = identifier.clone();
                        async move { Self::user_select_solver_for_id(identifier, map).await }
                            .boxed()
                    },
                )
            });
        InteractiveConfigEditor::new(
            "Assign a solver to each identifier",
            solver_map,
            identifier_editors,
            |map| {
                async {
                    for (domain, solver) in &map.domains {
                        if solver.is_empty() {
                            println!("Error: You must select a solver for {domain}");
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                .boxed()
            },
        )
        .edit_config()
        .await
    }

    async fn user_select_solver_for_id(
        identifier: Identifier,
        mut map: DomainSolverMap,
    ) -> Result<DomainSolverMap, Error> {
        let mut choices: Vec<_> = map
            .solvers
            .keys()
            .sorted()
            .map(|name| SolverChoice::ExistingSolver(name.as_str()))
            .collect();
        choices.push(SolverChoice::NewSolver);
        let choice = Select::new(
            "Select one of these existing solvers, or create a new one",
            choices,
        )
        .prompt()
        .context("No solver selected")?;
        match choice {
            SolverChoice::ExistingSolver(name) => {
                map.domains.insert(identifier, name.to_string());
            }
            SolverChoice::NewSolver => return Self::user_create_solver(identifier, map).await,
        }
        Ok(map)
    }

    async fn user_create_solver(
        identifier: Identifier,
        mut map: DomainSolverMap,
    ) -> Result<DomainSolverMap, Error> {
        #[allow(irrefutable_let_patterns)]
        if let Identifier::Dns(id) = &identifier {
            if id.is_wildcard() {
                println!(
                    "Note: {identifier} is a wildcard. Some CAs require you to use a DNS-based challenge for this identifier."
                );
            }
        }
        let domains = HashSet::from([identifier]);
        let builder_options: Vec<_> = CHALLENGE_SOLVER_REGISTRY
            .iter()
            .filter(|builder| builder.supported(&domains))
            .collect();
        println!("This identifier is supported by the following solvers:");
        let selected_builder = Select::new("Select a solver:", builder_options)
            .prompt()
            .context("No answer to solver prompt")?;
        let solver_config = selected_builder.build_interactive(&domains).await?;
        let solver_name = loop {
            let default_name = choose_solver_name(&solver_config, &map);
            let solver_name = Text::new("If you want, name this solver:")
                .with_initial_value(default_name.as_str())
                .with_help_message("Enter a name, or press ESC to use an autogenerated name")
                .with_validator(|name: &str| {
                    Ok(if name.is_empty() {
                        Validation::Invalid("Solver name cannot be empty".into())
                    } else {
                        Validation::Valid
                    })
                })
                .prompt_skippable()
                .context("No solver name given")?
                .unwrap_or(default_name);
            if map.solvers.contains_key(&solver_name) {
                println!(
                    "Error: A solver with name {solver_name} already exists - choose a different name"
                );
            } else {
                break solver_name;
            }
        };
        map.domains.insert(
            domains.into_iter().next().unwrap(/* Infallible */),
            solver_name.clone(),
        );
        map.solvers.insert(solver_name, solver_config);
        Ok(map)
    }

    async fn user_ask_cert_profile(
        issuer: &AcmeIssuerWithAccount<'_>,
        current: Option<String>,
    ) -> Result<Option<String>, Error> {
        let profiles = issuer.get_profiles().await?;
        if profiles.is_empty() {
            println!(
                "This CA does not support the ACME profiles extension. No profile can be selected."
            );
            return Ok(None);
        }
        let mut profile_options = Vec::with_capacity(profiles.len() + 1);
        for (name, description) in profiles {
            profile_options.push(AcmeProfile::new(name.clone(), description.clone()));
        }
        profile_options.push(AcmeProfile::new(
            "No profile".into(),
            "Choose this option to not use any of the above".into(),
        ));
        println!(
            "This CA offers several predefined profiles that affect the characteristics of the certificate."
        );
        println!(
            "Consult the CA documentation on what these profiles do exactly, and which profile to choose."
        );
        let selected_profile = Select::new("Choose a profile", profile_options)
            .with_help_message("↑↓ to move, enter to select, ESC to use current setting")
            .prompt_skippable()
            .context("No profile selected")?
            .map(|profile| profile.name);
        Ok(match selected_profile {
            None => current,
            Some(selected) => {
                if selected == "No profile" {
                    None
                } else {
                    Some(selected)
                }
            }
        })
    }

    fn user_ask_cert_lifetime(current: Option<u64>) -> Result<Option<u64>, Error> {
        println!(
            "Some CAs allow you to request a specific lifetime for the certificate (within a certain allowed range)."
        );
        println!(
            "You can enter such a desired lifetime for the certificate here, or leave it blank to not request any particular lifetime for the certificate."
        );
        println!(
            "Note that if the CA does not support this feature, or the requested value, issuance will fail."
        );
        println!("Consult the CA's documentation before using this feature.");
        let duration = CustomType::<ParsedDuration>::new("Select a lifetime for the certificate")
            .with_error_message(
                "Please type a valid duration, like '90 days' or '15d 2 hours 37min'",
            )
            .with_default(current.unwrap_or_default().into())
            .with_help_message("Press ESC or enter 0s to not use this feature")
            .prompt_skippable()
            .context("No answer to cert lifetime prompt")?
            .and_then(|duration| {
                if duration.is_zero() {
                    None
                } else {
                    Some(*duration)
                }
            })
            .map(|duration| duration.as_secs());
        Ok(duration)
    }

    fn user_ask_key_type(current: KeyType) -> Result<KeyType, Error> {
        println!(
            "The certificate can use one of the following supported cryptographic algorithms."
        );
        println!(
            "Note that not all CAs may support all of the choices below - consult the CA documentation."
        );
        println!(
            "If you are unsure what to select, just select the default option. RSA is also a very common choice."
        );
        let key_type = Select::new(
            "Choose a key type for the new certificate",
            CommandLineKeyType::VARIANTS
                .iter()
                .map(|k| (*k).into())
                .collect(),
        )
        .with_help_message(&format!("Press ESC to use current {current}"))
        .prompt_skippable()
        .context("No answer to key type prompt")?
        .unwrap_or(current);
        Ok(key_type)
    }

    fn user_ask_key_reuse(current: bool) -> Result<bool, Error> {
        println!("In certain setups, you want to reuse the same keypair in renewed certificates.");
        println!("This is generally not advised unless you really need it.");
        Ok(
            Confirm::new("Reuse the same keypair in renewed certificates")
                .with_default(current)
                .prompt_skippable()?
                .unwrap_or(current),
        )
    }

    fn user_ask_cert_name(current: String) -> Result<String, Error> {
        println!("If you want, you can give your new certificate a name to identify it later:");
        let cert_name = Text::new("Name your certificate:")
            .with_placeholder(&current)
            .with_help_message(&format!("Press ESC or leave empty to use {current}"))
            .prompt_skippable()
            .context("No answer to cert name prompt")?
            .map(|cert_name| {
                if cert_name.trim().is_empty() {
                    current.clone()
                } else {
                    cert_name
                }
            })
            .unwrap_or(current);
        Ok(cert_name)
    }

    fn user_ask_initial_cert_domains(
        issue_cmd: &IssueCommand,
    ) -> Result<HashSet<Identifier>, Error> {
        if let Some(domains) = &issue_cmd.domains {
            return Ok(domains.iter().cloned().sorted().collect());
        }
        // Domains are given per-solver
        if !issue_cmd.solver_configuration.is_empty() {
            return Ok(HashSet::new());
        }
        Self::user_ask_cert_domains(std::iter::empty())
    }

    fn user_ask_cert_domains<'a, I: Iterator<Item = &'a Identifier>>(
        current: I,
    ) -> Result<HashSet<Identifier>, Error> {
        let current = current.sorted().join(", ");
        let mut prompt = Text::new("Enter the domain name(s) for the new certificate:");
        prompt = if current.is_empty() {
            prompt.with_placeholder("example.com")
        } else {
            prompt.with_initial_value(&current)
        };
        let domains_string = prompt
            .with_help_message("Separate multiple names with spaces, commas, or both.")
            .with_validator(|input: &str| {
                if input.trim().is_empty() {
                    return Ok(Validation::Invalid("Domain cannot be empty".into()));
                }
                if input.split(',').any(|input| input.trim().is_empty()) {
                    return Ok(Validation::Invalid(
                        format!("Domain {input} contains empty component").into(),
                    ));
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
            .prompt_skippable()
            .context("No answer to domain prompt")?
            .unwrap_or(current);
        let mut domains = domains_string
            .split_whitespace()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<Identifier>().unwrap(/* Infallible */))
            .sorted()
            .collect::<HashSet<_>>();
        if domains.is_empty() {
            bail!("Domain list cannot be empty");
        }
        if domains.len() == 1 {
            // TODO: Wildcards: If given name is a wildcard, suggest base domain name instead
            let domain = domains.iter().next().unwrap(/* Infallible */);
            if domain.as_str().starts_with("www.") {
                let base_name = Identifier::from_str(
                    domain.as_str().strip_prefix("www.").unwrap(/* Infallible */),
                )?;
                let add_base_name = Confirm::new(&format!("It is common to also include {} in certificates, so that visitors can use either name. Do you want to add the base domain to your certificate?", base_name.to_string().green().on_black()))
                    .with_default(false)
                    .prompt_skippable()?.unwrap_or(false);
                if add_base_name {
                    domains.insert(base_name);
                }
            } else {
                let www_name = Identifier::from_str(&("www.".to_string() + domain.as_str()))?;
                let add_www = Confirm::new(&format!("It is common to also include {} in certificates, so that visitors can use either name. Do you want to add the www subdomain to your certificate?", www_name.to_string().green().on_black()))
                    .with_default(false)
                    .prompt_skippable()?.unwrap_or(false);
                if add_www {
                    domains.insert(www_name);
                }
            }
        }
        Ok(domains)
    }

    async fn user_select_ca_and_account(
        &mut self,
        issue_cmd: &IssueCommand,
    ) -> Result<(String, String), Error> {
        let issuer = if let Some(preselected_ca) = &issue_cmd.ca {
            preselected_ca.clone()
        } else {
            self.interactive_select_ca(true)?
        };

        let account = if let Some(preselected_account) = &issue_cmd.account {
            preselected_account.clone()
        } else {
            let issuer = self
                .client
                .get_ca(&issuer)
                .ok_or(anyhow!("CA {issuer} not found"))?;
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

    fn user_select_ca(client: &Certonaut<CB>, allow_creation: bool) -> Result<CaChoice, Error> {
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

    fn user_create_ca(
        client: &mut Certonaut<CB>,
    ) -> Result<CertificateAuthorityConfiguration, Error> {
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
        let mut new_default_prompt =
            Confirm::new("Do you want to use this CA as your default?").with_default(false);
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
        let num_accounts = ca.num_accounts();
        if num_accounts == 0 {
            if allow_creation {
                return Ok(AccountChoice::NewAccount);
            }
            bail!("No accounts configured for CA {}", ca.config.name)
        }
        // If the user has only a single account, we select that by default
        // because that's a very common setup. The user can still request for new accounts to be
        // created explicitly.
        if num_accounts == 1 {
            return Ok(AccountChoice::ExistingAccount(
                ca.get_accounts().next().unwrap().config.clone(),
            ));
        }
        let mut choices = ca
            .get_accounts()
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
            "You can provide one or more contact addresses to the CA. Please provide a comma-separated list \
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
        let account_num = ca.num_accounts();
        let account_name = if account_num > 0 {
            format!("{ca_name} ({account_num})")
        } else {
            ca_name.to_string()
        };
        let account_id = format!("{ca_id}@{account_num}");
        Certonaut::<CB>::create_account(
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

    async fn user_create_account_ca_specific_features(
        ca: &AcmeIssuer,
    ) -> anyhow::Result<Option<bool>> {
        let ca_name = ca.config.name.as_str().green();
        let acme_client = ca.client().await?;
        let directory = acme_client.get_directory();
        let mut tos_status = None;
        if let Some(meta) = &directory.meta {
            if let Some(website) = &meta.website {
                println!(
                    "If this is your first time using {ca_name}, you may want to review this website:",
                );
                println!("{}", website.as_str().blue());
            }
            if let Some(tos) = &meta.terms_of_service {
                println!(
                    "Please familiarize yourself with {ca_name} terms of service, available at this URL:",
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
                    bail!(
                        "EAB is required for this CA. Please review the CA's website to find instructions, or select a different CA."
                    )
                }
            }
        }
        Ok(tos_status)
    }

    fn user_ask_installer(
        current: Option<InstallerConfiguration>,
    ) -> Result<Option<InstallerConfiguration>, Error> {
        println!("In many cases, you will want to run a script to install the certificate.");
        println!(
            "For instance, you may want to reload a webserver or copy the certificate to multiple instances in a distributed environment."
        );
        println!(
            "You can specify such a custom script here. The script receives two environment variables:"
        );
        println!(
            "$RENEWED_LINEAGE - points to the directory containing the certificate and key files."
        );
        println!(
            "$RENEWED_DOMAINS - contains the domain names of the certificate, separated by spaces."
        );
        println!(
            "(The above is compatible to certbot, so scripts written for certbot should just work)"
        );
        let script_raw = if let Some(InstallerConfiguration::Script { script }) = &current {
            script.to_string()
        } else {
            String::new()
        };
        let script = Text::new("Shell command to run after issuance?")
            .with_initial_value(&script_raw)
            .with_help_message("Enter a shell command, or leave empty to run no command")
            .prompt_skippable()
            .context("No answer to shell command prompt")?
            .map_or(current, |script| {
                if script.is_empty() {
                    None
                } else {
                    Some(InstallerConfiguration::Script { script })
                }
            });
        Ok(script)
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
            (CaChoice::ExistingCa(self_ca), CaChoice::ExistingCa(other_ca)) => {
                Some(self_ca.name.cmp(&other_ca.name))
            }
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
                }
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
            (
                AccountChoice::ExistingAccount(self_acc),
                AccountChoice::ExistingAccount(other_acc),
            ) => self_acc.identifier == other_acc.identifier,
            _ => false,
        }
    }
}

impl PartialOrd for AccountChoice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (
                AccountChoice::ExistingAccount(self_acc),
                AccountChoice::ExistingAccount(other_acc),
            ) => Some(self_acc.name.cmp(&other_acc.name)),
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

#[derive(Debug, Clone)]
pub struct CertChoice {
    id: String,
    display_name: String,
    domains: Vec<String>,
}

impl Display for CertChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = &self.id;
        let display_name = &self.display_name;
        let domains = self.domains.join(", ");
        write!(f, "{display_name} (ID: {id}) ({domains})")
    }
}

pub enum SolverChoice<'a> {
    ExistingSolver(&'a str),
    NewSolver,
}

impl Display for SolverChoice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverChoice::ExistingSolver(solver) => {
                write!(f, "{solver}")
            }
            SolverChoice::NewSolver => f.write_str("Create new solver"),
        }
    }
}
