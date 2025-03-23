use crate::acme::client::{AcmeClient, DownloadedCertificate};
use crate::acme::error::Problem;
use crate::acme::object::{
    AccountStatus, AcmeRenewalIdentifier, AuthorizationStatus, ChallengeStatus, InnerChallenge,
    NewOrderRequest, Order, OrderStatus,
};
use crate::cert::{ParsedX509Certificate, create_and_sign_csr};
use crate::challenge_solver::KeyAuthorization;
use crate::config::{
    CertificateAuthorityConfiguration, CertificateAuthorityConfigurationWithAccounts,
};
use crate::error::{IssueContext, IssueResult};
use crate::state::types::external::RenewalInformation;
use crate::time::current_time_truncated;
use crate::{AcmeAccount, Authorizer, acme, new_acme_client};
use anyhow::{Context, Error, anyhow, bail};
use rand::Rng;
use rcgen::CertificateSigningRequest;
use std::collections::HashMap;
use std::time::Duration;
use time::error::ConversionRange;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use url::Url;

#[derive(Debug)]
pub struct AcmeIssuer {
    pub config: CertificateAuthorityConfiguration,
    client: OnceCell<AcmeClient>,
    accounts: HashMap<String, AcmeAccount>,
}

impl AcmeIssuer {
    pub fn try_new(config: CertificateAuthorityConfigurationWithAccounts) -> anyhow::Result<Self> {
        let client = OnceCell::new();
        let mut accounts = HashMap::new();
        for account_config in config.accounts {
            let account_id = account_config.identifier.clone();
            let account = AcmeAccount::load_existing(account_config)?;
            if let Some(old) = accounts.insert(account_id, account) {
                let id = old.config.identifier;
                bail!("Duplicate account id {id} in configuration");
            }
        }
        Ok(Self {
            client,
            accounts,
            config: config.inner,
        })
    }

    #[cfg(test)]
    fn override_client(&self, client: AcmeClient) -> anyhow::Result<()> {
        self.client
            .set(client)
            .context("AcmeIssuer already initialized")
    }

    pub async fn client(&self) -> Result<&AcmeClient, Error> {
        self.client
            .get_or_try_init(|| async { new_acme_client(&self.config).await })
            .await
    }

    pub fn current_config(&self) -> CertificateAuthorityConfigurationWithAccounts {
        CertificateAuthorityConfigurationWithAccounts {
            inner: self.config.clone(),
            accounts: self
                .accounts
                .values()
                .map(|account| &account.config)
                .cloned()
                .collect(),
        }
    }

    pub fn with_account(&self, account_id: &str) -> Option<AcmeIssuerWithAccount> {
        let account = self.accounts.get(account_id)?;
        Some(AcmeIssuerWithAccount {
            issuer: self,
            account,
        })
    }

    pub fn get_account(&self, account_id: &str) -> Option<&AcmeAccount> {
        self.accounts.get(account_id)
    }

    pub fn get_accounts(&self) -> impl Iterator<Item = &AcmeAccount> {
        self.accounts.values()
    }

    pub fn num_accounts(&self) -> usize {
        self.accounts.len()
    }

    pub fn add_account(&mut self, account: AcmeAccount) {
        self.accounts
            .insert(account.config.identifier.clone(), account);
    }

    pub fn remove_account(&mut self, account_id: &str) -> Option<AcmeAccount> {
        self.accounts.remove(account_id)
    }
}

#[derive(Debug, Clone)]
pub struct AcmeIssuerWithAccount<'a> {
    pub issuer: &'a AcmeIssuer,
    pub account: &'a AcmeAccount,
}

impl AcmeIssuerWithAccount<'_> {
    async fn client(&self) -> Result<&AcmeClient, Error> {
        self.issuer.client().await
    }

    async fn get_cert_from_finalized_order(
        &self,
        order: Order,
    ) -> IssueResult<DownloadedCertificate> {
        debug_assert_eq!(
            order.status,
            OrderStatus::Valid,
            "BUG: Certificate cannot be downloaded from non-valid order"
        );
        let certificate_url = order.certificate.ok_or(anyhow!(
            "CA did not provide a certificate URL for final order"
        ))?;
        debug!("Final certificate available @ {certificate_url}");
        let cert = self
            .client()
            .await?
            .download_certificate(&self.account.jwk, &certificate_url)
            .await
            .context("Downloading certificate")?;
        info!("Successfully issued a certificate!");
        Ok(cert)
    }

    pub async fn issue(
        &self,
        cert_key: &rcgen::KeyPair,
        cert_lifetime: Option<Duration>,
        authorizers: Vec<Authorizer>,
        replaces: Option<AcmeRenewalIdentifier>,
    ) -> IssueResult<DownloadedCertificate> {
        let identifiers: Vec<_> = authorizers
            .iter()
            .map(|authorizer| authorizer.identifier.clone())
            .collect();
        let names = identifiers.join(", ");
        info!(
            "Issuing certificate for {names} at CA {}",
            self.issuer.config.name
        );
        let csr = create_and_sign_csr(cert_key, identifiers.clone())?;
        let (not_before, not_after) = match cert_lifetime {
            Some(lifetime) => {
                let not_before = current_time_truncated();
                let not_after = ::time::Duration::try_from(lifetime)
                    .and_then(|lifetime| not_before.checked_add(lifetime).ok_or(ConversionRange))
                    .context("Range error computing cert validity dates")
                    .client_failure()?;
                (Some(not_before), Some(not_after))
            }
            None => (None, None),
        };
        let request = NewOrderRequest {
            identifiers,
            not_before,
            not_after,
            replaces,
        };
        self.order_and_authorize(csr, request, authorizers).await
    }

    async fn order_and_authorize(
        &self,
        csr: CertificateSigningRequest,
        request: NewOrderRequest,
        authorizers: Vec<Authorizer>,
    ) -> IssueResult<DownloadedCertificate> {
        let (order_url, mut order) = self.new_order(request).await?;
        let client = self.client().await?;
        match order.status {
            OrderStatus::Valid => {
                debug!(
                    "CA claims order is already valid (but we haven't done anything yet?), downloading certificate anyway"
                );
                return self.get_cert_from_finalized_order(order).await;
            }
            OrderStatus::Ready | OrderStatus::Processing => {
                debug!(
                    "New order is already ready/processing, finalizing order and downloading certificate"
                );
                let final_order = client
                    .finalize_order(&self.account.jwk, order, &order_url, &csr)
                    .await
                    .context("Polling finalized order")?;
                return self.get_cert_from_finalized_order(final_order).await;
            }
            OrderStatus::Invalid => {
                if let Some(error) = order.error {
                    return Err((
                        error,
                        anyhow!("New order has unacceptable status (invalid)"),
                    )
                        .into());
                }
                return anyhow!("New order has unacceptable status (invalid)").ca_failure();
            }
            OrderStatus::Pending => {
                self.authorize(order, authorizers)
                    .await
                    .context("Error authorizing certificate issuance")?;
                info!("Finished authorizing all identifiers");
            }
        }
        debug!("Re-fetching fully authorized order ({order_url})");
        order = client
            .get_order(&self.account.jwk, &order_url)
            .await
            .context("Re-fetching fully authorized order")?;
        match order.status {
            OrderStatus::Valid => {
                debug!(
                    "CA claims order is already valid (but we haven't finalized?), downloading certificate anyway"
                );
                self.get_cert_from_finalized_order(order).await
            }
            OrderStatus::Ready | OrderStatus::Processing => {
                debug!("Finalizing order");
                let final_order = client
                    .finalize_order(&self.account.jwk, order, &order_url, &csr)
                    .await
                    .context("Error finalizing order")?;
                self.get_cert_from_finalized_order(final_order).await
            }
            OrderStatus::Pending => {
                if let Some(error) = order.error {
                    error.into_result().context(
                        "Order is still pending after having authorized all identifiers",
                    )?;
                }
                anyhow!("Order is still pending after having authorized all identifiers")
                    .ca_failure()
            }
            OrderStatus::Invalid => {
                if let Some(error) = order.error {
                    error.into_result().context("Order has invalid status")?;
                }
                anyhow!("Order has invalid status (no error reported by CA)").ca_failure()
            }
        }
    }

    async fn new_order(&self, mut request: NewOrderRequest) -> IssueResult<(Url, Order)> {
        let client = self.client().await?;
        if client.get_directory().renewal_info.is_none() {
            // draft-ietf-acme-ari-08: Clients SHOULD NOT include this field if the ACME Server has not indicated
            // that it supports this protocol by advertising the renewalInfo resource in its Directory.
            request.replaces = None;
        }
        let (order_url, order) = match client.new_order(&self.account.jwk, &request).await {
            Ok(success) => Ok(success),
            Err(e @ acme::error::Error::AcmeProblem(_)) => {
                if request.replaces.is_some() {
                    // If an order with a "replaces" field fails, the CA may be unhappy with the
                    // replacement. Try again without.
                    warn!("The CA refused a new order replacing an older certificate: {e}");
                    warn!("Trying again without replacing the old certificate");
                    request.replaces = None;
                    client.new_order(&self.account.jwk, &request).await
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
        .context("Error creating new order")?;
        debug!("Order URL: {}", order_url);
        Ok((order_url, order))
    }

    async fn authorize(
        &self,
        order: Order,
        mut authorizers: Vec<Authorizer>,
    ) -> anyhow::Result<()> {
        let client = self.client().await?;
        for authz_url in order.authorizations {
            debug!("Checking authorization @ {authz_url}");
            let authz = client
                .get_authorization(&self.account.jwk, &authz_url)
                .await
                .context("Retrieving authorization from server")?;
            match authz.status {
                AuthorizationStatus::Valid => {
                    debug!("Authorization already valid");
                    // Skip
                }
                AuthorizationStatus::Pending => {
                    let id = authz.identifier;
                    info!("Found pending authorization for {id}, trying to authorize");
                    let mut challenge_solver =
                        authorizers.swap_remove(authorizers.iter().position(|authorizer| authorizer.identifier == id).ok_or(
                            anyhow!(
                                "Order contains pending authorization for {id}, but this identifier was not part of our requested order"
                            ),
                        )?);
                    let solver_name_long = challenge_solver.solver.long_name();
                    let solver_name_short = challenge_solver.solver.short_name();
                    let chosen_challenge = authz
                        .challenges
                        .into_iter()
                        .filter(|challenge| matches!(challenge.status, ChallengeStatus::Pending))
                        .filter(|challenge| !matches!(challenge.inner_challenge, InnerChallenge::Unknown))
                        .find(|challenge| challenge_solver.solver.supports_challenge(&challenge.inner_challenge))
                        .ok_or(anyhow!(
                            "Authorization for {id} did not contain any pending challenge supported by {solver_name_long}"
                        ))?;
                    let challenge_type = chosen_challenge.inner_challenge.get_type().to_string();
                    debug!(
                        "{solver_name_short} selected {challenge_type} challenge @ {}",
                        chosen_challenge.url
                    );

                    // TODO: Timeout solver?

                    // Setup
                    challenge_solver
                        .solver
                        .deploy_challenge(&self.account.jwk, &id, chosen_challenge.inner_challenge)
                        .await
                        .context(format!(
                            "Setting up challenge solver {solver_name_long} for {id}"
                        ))?;

                    debug!(
                        "{solver_name_short} reported successful challenge deployment, attempting validation now"
                    );

                    // TODO: Preflight checks? By us or by solver?

                    // Validation
                    client
                        .validate_challenge(&self.account.jwk, &chosen_challenge.url)
                        .await
                        .context(format!(
                            "Error validating {challenge_type} challenge for {id} with challenge solver {solver_name_long}"
                        ))?;

                    info!("Successfully validated challenge for {id}");

                    // Cleanup
                    if let Err(e) = challenge_solver.solver.cleanup_challenge().await {
                        warn!(
                            "Challenge solver {solver_name_long} for {id} encountered an error during cleanup: {e:#}"
                        );
                    }
                }
                AuthorizationStatus::Invalid => {
                    let id = &authz.identifier;
                    let problems: Vec<Problem> = authz
                        .challenges
                        .into_iter()
                        .filter_map(|challenge| challenge.error)
                        .collect();
                    let mut problem_string = String::new();
                    for problem in problems {
                        problem_string.push('\n');
                        problem_string.push_str(&problem.to_string());
                    }
                    bail!(
                        "Failed to authorize {id}. The CA reported these problems: {problem_string}"
                    );
                }
                AuthorizationStatus::Deactivated
                | AuthorizationStatus::Expired
                | AuthorizationStatus::Revoked => {
                    let id = &authz.identifier;
                    bail!(
                        "Authorization for {id} is in an invalid status (deactivated, expired, or revoked)"
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn deactivate_account(&self) -> Result<(), Error> {
        let client = self.client().await?;
        let deactivated_account = client
            .deactivate_account(&self.account.jwk, &self.account.config.url)
            .await?;
        if matches!(deactivated_account.status, AccountStatus::Deactivated) {
            Ok(())
        } else {
            bail!(
                "ACME account has invalid status {} after deactivation",
                deactivated_account.status
            )
        }
    }

    pub async fn get_renewal_info(
        &self,
        cert_id: String,
        cert: &ParsedX509Certificate,
    ) -> anyhow::Result<Option<RenewalInformation>> {
        let Some(renewal_identifier) = &cert.acme_renewal_identifier else {
            let serial = &cert.serial;
            debug!(
                "Cert with serial {serial} does not support ACME Renewal Information (missing Authority Key Identifier extension)"
            );
            return Ok(None);
        };
        let client = self.client().await?;
        match client.get_renewal_info(renewal_identifier).await {
            Ok(renewal_info) => {
                debug!("ARI server response: {renewal_info}");
                let now = ::time::OffsetDateTime::now_utc();
                if let Some(explanation_url) = renewal_info.renewal_info.explanation_url {
                    info!(
                        "The server attached an explanation URL to a recently retrieved ACME Renewal Information. You may want to review it:"
                    );
                    info!("{explanation_url}");
                }
                let mut window = renewal_info.renewal_info.suggested_window;
                if window.end > cert.validity.not_after {
                    warn!(
                        "The CA provided an ARI window where the end time is after the certificate's expiry. Clamping the window."
                    );
                    window.end = cert.validity.not_after;
                }
                let start_unix = window.start.unix_timestamp();
                let end_unix = window.end.unix_timestamp();
                if start_unix >= end_unix {
                    return Err(acme::error::Error::ProtocolViolation(
                        "Window end time is at or after the start time",
                    ))
                    .context("Determining ARI window");
                }
                let mut rng = rand::rng();
                let random_unix = rng.random_range(start_unix..=end_unix);
                let random_time = ::time::OffsetDateTime::from_unix_timestamp(random_unix)
                    .context("Determining ARI window: Invalid time range provided by server")?;
                debug!("Determined ARI random renewal time @ {random_time}");
                Ok(Some(RenewalInformation {
                    cert_id,
                    fetched_at: now,
                    renewal_time: random_time,
                    next_update: renewal_info.retry_after.into(),
                }))
            }
            Err(acme::error::Error::FeatureNotSupported) => {
                let ca = &self.issuer.config.name;
                debug!(
                    "CA {ca} does not support ACME Renewal Information, can not fetch online renewal information"
                );
                Ok(None)
            }
            Err(e) => {
                Err(Error::new(e).context("Failed to fetch ACME Renewal Information from CA"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;
    use crate::acme::object::{Authorization, Challenge, Directory, HttpChallenge, Token};
    use crate::challenge_solver::NullSolver;
    use crate::crypto::asymmetric::{Curve, KeyType, new_key};
    use crate::util::serde_helper::PassthroughBytes;

    use crate::config::{AccountConfiguration, Identifier};
    use std::path::PathBuf;
    use std::str::FromStr;

    fn setup_fake_ca(fake_url: &Url) -> anyhow::Result<AcmeIssuer> {
        let fake_config = CertificateAuthorityConfigurationWithAccounts {
            inner: CertificateAuthorityConfiguration {
                name: "Fake CA".to_string(),
                identifier: "fake".to_string(),
                acme_directory: fake_url.clone(),
                public: false,
                testing: false,
                default: false,
            },
            accounts: vec![AccountConfiguration {
                name: "Fake Account".to_string(),
                identifier: "fake".to_string(),
                key_file: PathBuf::from("testdata/account.key"),
                url: fake_url.clone(),
            }],
        };
        AcmeIssuer::try_new(fake_config)
    }

    #[tokio::test]
    async fn test_issue_with_cached_authz() -> Result<(), Error> {
        let fake_url = Url::parse("https://fake.invalid")?;
        let issuer = setup_fake_ca(&fake_url)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;
        let mut mock_client = AcmeClient::faux();
        let fake_directory = Directory {
            new_nonce: fake_url.clone(),
            new_account: fake_url.clone(),
            new_order: fake_url.clone(),
            new_authz: None,
            revoke_cert: fake_url.clone(),
            key_change: fake_url.clone(),
            renewal_info: None,
            meta: None,
        };
        let new_order = Ok((
            fake_url.clone(),
            Order {
                status: OrderStatus::Ready,
                expires: None,
                identifiers: vec![],
                not_before: None,
                not_after: None,
                error: None,
                authorizations: vec![],
                finalize: fake_url.clone(),
                certificate: None,
            },
        ));
        let finalized_order = Ok(Order {
            status: OrderStatus::Valid,
            expires: None,
            identifiers: vec![],
            not_before: None,
            not_after: None,
            error: None,
            authorizations: vec![],
            finalize: fake_url.clone(),
            certificate: Some(fake_url.clone()),
        });
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        // SAFETY: lifetime of &fake_directory is the entire test
        unsafe {
            faux::when!(mock_client.get_directory).then_unchecked(|()| &fake_directory);
        }
        faux::when!(mock_client.new_order)
            .once()
            .then_return(new_order);
        faux::when!(mock_client.finalize_order)
            .once()
            .then_return(finalized_order);
        faux::when!(mock_client.download_certificate)
            .once()
            .then_return(certificate);
        issuer.override_client(mock_client)?;

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                None,
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn test_issue_with_single_authz() -> Result<(), Error> {
        let fake_url = Url::parse("https://fake.invalid")?;
        let fake_order_url = Url::parse("https://fake.invalid/order")?;
        let fake_authz_url = Url::parse("https://fake.invalid/authz")?;
        let fake_challenge_url = Url::parse("https://fake.invalid/challenge")?;
        let fake_finalize_url = Url::parse("https://fake.invalid/finalize")?;
        let fake_cert_url = Url::parse("https://fake.invalid/cert")?;
        let issuer = setup_fake_ca(&fake_url)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;
        let mut mock_client = AcmeClient::faux();
        let fake_directory = Directory {
            new_nonce: fake_url.clone(),
            new_account: fake_url.clone(),
            new_order: fake_url.clone(),
            new_authz: None,
            revoke_cert: fake_url.clone(),
            key_change: fake_url.clone(),
            renewal_info: None,
            meta: None,
        };
        let new_order = Ok((
            fake_order_url.clone(),
            Order {
                status: OrderStatus::Pending,
                expires: None,
                identifiers: vec![],
                not_before: None,
                not_after: None,
                error: None,
                authorizations: vec![fake_authz_url.clone()],
                finalize: fake_finalize_url.clone(),
                certificate: None,
            },
        ));
        let pending_authorization = Ok(Authorization {
            identifier: Identifier::from_str("example.com")?.into(),
            status: AuthorizationStatus::Pending,
            expires: None,
            challenges: vec![Challenge {
                url: fake_challenge_url.clone(),
                status: ChallengeStatus::Pending,
                validated: None,
                error: None,
                inner_challenge: InnerChallenge::Http(HttpChallenge {
                    token: Token::from_str("some-token")?,
                }),
            }],
            wildcard: false,
        });
        let validated_challenge = Ok(Challenge {
            url: fake_challenge_url.clone(),
            status: ChallengeStatus::Valid,
            validated: None,
            error: None,
            inner_challenge: InnerChallenge::Http(HttpChallenge {
                token: Token::from_str("some-token")?,
            }),
        });
        let ready_order = Ok(Order {
            status: OrderStatus::Ready,
            expires: None,
            identifiers: vec![],
            not_before: None,
            not_after: None,
            error: None,
            authorizations: vec![fake_authz_url.clone()],
            finalize: fake_finalize_url.clone(),
            certificate: None,
        });
        let finalized_order = Ok(Order {
            status: OrderStatus::Valid,
            expires: None,
            identifiers: vec![],
            not_before: None,
            not_after: None,
            error: None,
            authorizations: vec![fake_authz_url.clone()],
            finalize: fake_finalize_url.clone(),
            certificate: Some(fake_cert_url.clone()),
        });
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        // SAFETY: lifetime of &fake_directory is the entire test
        unsafe {
            faux::when!(mock_client.get_directory).then_unchecked(|()| &fake_directory);
        }
        faux::when!(mock_client.new_order)
            .once()
            .then_return(new_order);
        faux::when!(mock_client.get_authorization(_, fake_authz_url))
            .once()
            .then_return(pending_authorization);
        faux::when!(mock_client.validate_challenge(_, fake_challenge_url))
            .once()
            .then_return(validated_challenge);
        faux::when!(mock_client.get_order(_, fake_order_url))
            .once()
            .then_return(ready_order);
        faux::when!(mock_client.finalize_order)
            .once()
            .then_return(finalized_order);
        faux::when!(mock_client.download_certificate(_, fake_cert_url))
            .once()
            .then_return(certificate);
        issuer.override_client(mock_client)?;

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                None,
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }
}
