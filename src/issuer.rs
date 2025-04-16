use crate::acme::client::{AcmeClient, DownloadedCertificate};
use crate::acme::error::Problem;
use crate::acme::object::{
    AccountStatus, AcmeRenewalIdentifier, Authorization, AuthorizationStatus, Challenge,
    ChallengeStatus, InnerChallenge, NewOrderRequest, Order, OrderStatus,
};
use crate::cert::{ParsedX509Certificate, create_and_sign_csr};
use crate::config::{
    CertificateAuthorityConfiguration, CertificateAuthorityConfigurationWithAccounts,
};
use crate::dns::resolver::Resolver;
use crate::error::{IssueContext, IssueResult};
use crate::state::types::external::RenewalInformation;
use crate::time::current_time_truncated;
use crate::{AcmeAccount, Authorizer, Identifier, acme, new_acme_client};
use anyhow::{Context, Error, anyhow, bail};
use itertools::Itertools;
use rand::Rng;
use rcgen::CertificateSigningRequest;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use time::error::ConversionRange;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};
use url::Url;

#[derive(Debug)]
pub struct AcmeIssuer {
    pub config: CertificateAuthorityConfiguration,
    client: OnceCell<AcmeClient>,
    accounts: HashMap<String, AcmeAccount>,
    resolver: Arc<Resolver>,
}

impl AcmeIssuer {
    pub fn try_new(
        config: CertificateAuthorityConfigurationWithAccounts,
        resolver: Arc<Resolver>,
    ) -> anyhow::Result<Self> {
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
            resolver,
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
        let client = self.client().await.context(format!(
            "Failed to fetch ACME Renewal Information for {cert_id} from CA"
        ))?;
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
                let start_unix = window.start.unix_timestamp_nanos();
                let end_unix = window.end.unix_timestamp_nanos();
                if start_unix >= end_unix {
                    return Err(acme::error::Error::ProtocolViolation(
                        "Window end time is at or after the start time",
                    ))
                    .context("Determining ARI window");
                }
                let mut rng = rand::rng();
                let random_unix = rng.random_range(start_unix..=end_unix);
                let random_time = ::time::OffsetDateTime::from_unix_timestamp_nanos(random_unix)
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
                let ca = &self.config.name;
                debug!(
                    "CA {ca} does not support ACME Renewal Information, can not fetch online renewal information"
                );
                Ok(None)
            }
            Err(e) => Err(Error::new(e).context(format!(
                "Failed to fetch ACME Renewal Information for cert {cert_id} from CA"
            ))),
        }
    }

    pub async fn get_profiles(&self) -> anyhow::Result<&HashMap<String, String>> {
        static EMPTY_HASHMAP: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);
        let client = self.client().await?;
        let profiles = client
            .get_directory()
            .meta
            .as_ref()
            .map(|meta| &meta.profiles);
        Ok(match profiles {
            Some(profiles) => profiles,
            None => &EMPTY_HASHMAP,
        })
    }

    pub async fn validate_profile(&self, profile: Option<&String>) -> anyhow::Result<()> {
        let ca = &self.config.name;
        if let Some(profile) = profile {
            let profiles = self.get_profiles().await?;
            if profiles.get(profile).is_none() {
                let mut options = profiles.keys().join(", ");
                if options.is_empty() {
                    options = "(the CA does not offer any profiles)".into();
                }
                bail!(
                    "{profile} is not a profile currently offered by CA {ca}. Available profiles are {options}"
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AcmeIssuerWithAccount<'a> {
    pub issuer: &'a AcmeIssuer,
    pub account: &'a AcmeAccount,
}

impl AcmeIssuerWithAccount<'_> {
    #[inline]
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
        profile: Option<String>,
    ) -> IssueResult<DownloadedCertificate> {
        let names = authorizers.iter().map(|auth| &auth.identifier).join(", ");
        let identifiers: Vec<_> = authorizers
            .iter()
            .map(|authorizer| authorizer.identifier.clone().into())
            .collect();
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
            profile,
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
            let id = &authz.identifier;
            let wildcard = authz.wildcard;
            let name = if wildcard {
                format!("*.{id}")
            } else {
                id.to_string()
            };
            match authz.status {
                AuthorizationStatus::Valid => {
                    debug!("Authorization already valid");
                    // Skip
                }
                AuthorizationStatus::Pending => {
                    self.solve_challenge(authz, &mut authorizers)
                        .await
                        .context(format!(
                            "Failed to obtain issuance authorization for {name}"
                        ))?;
                }
                AuthorizationStatus::Invalid => {
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
                        "Failed to authorize {name}. The CA reported these problems: {problem_string}"
                    );
                }
                AuthorizationStatus::Deactivated
                | AuthorizationStatus::Expired
                | AuthorizationStatus::Revoked => {
                    bail!(
                        "Authorization for {name} is in an invalid status (deactivated, expired, or revoked)"
                    );
                }
            }
        }
        Ok(())
    }

    async fn solve_challenge(
        &self,
        authz: Authorization,
        authorizers: &mut Vec<Authorizer>,
    ) -> anyhow::Result<Challenge> {
        let client = self.client().await?;
        let acme_id = authz.identifier;
        let wildcard = authz.wildcard;
        let id = if wildcard {
            Identifier::try_from_with_wildcard(acme_id)
        } else {
            Identifier::try_from(acme_id)
        }?;
        info!("Found pending authorization for {id}, trying to authorize");
        let mut challenge_solver =
            authorizers.swap_remove(authorizers.iter().position(|authorizer| authorizer.identifier == id).ok_or(
                anyhow!("Order contains pending authorization for {id}, but this identifier was not part of our requested order"),
            )?);
        let solver_name_long = challenge_solver.solver.long_name();
        let solver_name_short = challenge_solver.solver.short_name();
        let chosen_challenge = authz
            .challenges
            .into_iter()
            .filter(|challenge| matches!(challenge.status, ChallengeStatus::Pending))
            .filter(|challenge| !matches!(challenge.inner_challenge, InnerChallenge::Unknown))
            .find(|challenge| challenge_solver.solver.supports_challenge(&challenge.inner_challenge))
            .ok_or(anyhow!("Authorization for {id} did not contain any pending challenge supported by {solver_name_long} (solver configuration invalid?)"))?;
        let challenge_type = chosen_challenge.inner_challenge.get_type().to_string();
        debug!(
            "{solver_name_short} selected {challenge_type} challenge @ {}",
            chosen_challenge.url
        );

        let challenge_id = match &chosen_challenge.inner_challenge {
            InnerChallenge::Dns(_) => self.identifier_to_dns01_fqdn(id.clone()).await?,
            _ => id.clone(),
        };

        // TODO: Timeout solver?

        // Setup
        challenge_solver
            .solver
            .deploy_challenge(
                &self.account.jwk,
                &challenge_id,
                chosen_challenge.inner_challenge,
            )
            .await
            .context(format!(
                "Setting up challenge solver {solver_name_long} for {id} (challenge domain: {challenge_id})"
            ))?;

        debug!(
            "{solver_name_short} reported successful challenge deployment for {id} (challenge domain: {challenge_id}), attempting validation now"
        );

        // TODO: Preflight checks if enabled

        // Validation
        let maybe_err = client
            .validate_challenge(&self.account.jwk, &chosen_challenge.url)
            .await
            .context(format!(
                "Error validating {challenge_type} challenge for {id} (challenge domain: {challenge_id}) with challenge solver {solver_name_long}"
            ));

        // Cleanup
        if let Err(e) = challenge_solver.solver.cleanup_challenge().await {
            warn!(
                "Challenge solver {solver_name_long} for {id} (challenge domain: {challenge_id}) encountered an error during cleanup: {e:#}"
            );
        }

        let validated_challenge = maybe_err?;
        info!("Successfully validated challenge for {id}");
        Ok(validated_challenge)
    }

    /// Translate a given identifier to its dns-01 challenge FQDN. For example, the domain `example.com` would
    /// have a challenge FQDN of `_acme-challenge.example.com`. This function also resolves any CNAMEs present at
    /// the original identifier: For instance, if `_acme-challenge.example.com` points to `challenge-target.example.org`
    /// via CNAME, then this function returns `challenge-target.example.org`.
    ///
    /// # Errors
    ///
    /// - If the given identifier is not compatible with a dns-01 challenge (e.g. IP address)
    /// - If the `_acme-challenge` FQDN cannot be constructed (e.g. DNS length limit exceeded)
    ///
    /// # Notes
    ///
    /// This function does not currently fail if CNAME resolution fails, but logs an error instead and assumes that no CNAME is present
    async fn identifier_to_dns01_fqdn(&self, identifier: Identifier) -> anyhow::Result<Identifier> {
        let acme_challenge = match identifier {
            Identifier::Dns(dns_name) => dns_name.to_acme_challenge_name().context(format!(
                "Failed to determine _acme-challenge subdomain for {dns_name}"
            ))?,
        };
        let cname_target = match self
            .issuer
            .resolver
            .resolve_cname_chain(acme_challenge.clone())
            .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                error!(
                    "Failed to resolve CNAME chain for {acme_challenge}, assuming no CNAME present: {e:#}"
                );
                acme_challenge.clone()
            }
        };
        debug!("Resolved CNAME for {acme_challenge} to {cname_target}");
        Ok(Identifier::Dns(cname_target))
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
        self.issuer.get_renewal_info(cert_id, cert).await
    }

    pub async fn get_profiles(&self) -> anyhow::Result<&HashMap<String, String>> {
        self.issuer.get_profiles().await
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;
    use crate::acme::client::RenewalResponse;
    use crate::acme::object::{
        Authorization, Challenge, Directory, HttpChallenge, Metadata, RenewalInfo, SuggestedWindow,
        Token,
    };
    use crate::cert::Validity;
    use crate::challenge_solver::NullSolver;
    use crate::config::AccountConfiguration;
    use crate::crypto::asymmetric::{Curve, KeyType, new_key};
    use crate::util::serde_helper::PassthroughBytes;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::LazyLock;
    use std::time::SystemTime;
    use x509_parser::num_bigint::BigUint;

    fn test_url() -> Url {
        static TEST_URL: LazyLock<Url> =
            LazyLock::new(|| Url::parse("https://fake.invalid/").unwrap());
        TEST_URL.clone()
    }

    fn create_order(
        status: OrderStatus,
        authorizations: Vec<Url>,
        error: Option<Problem>,
        certificate: Option<Url>,
    ) -> Order {
        Order {
            status,
            expires: None,
            identifiers: vec![],
            not_before: None,
            not_after: None,
            error,
            authorizations,
            finalize: test_url().join("finalize").unwrap(),
            certificate,
            replaces: None,
            profile: None,
        }
    }

    fn setup_fake_issuer(mut mock_client: AcmeClient) -> anyhow::Result<AcmeIssuer> {
        let fake_directory = Box::new(Directory {
            new_nonce: test_url(),
            new_account: test_url(),
            new_order: test_url(),
            new_authz: None,
            revoke_cert: test_url(),
            key_change: test_url(),
            renewal_info: Some(test_url()),
            meta: None,
        });
        let fake_directory: &'static Directory = Box::leak(fake_directory);
        let fake_config = CertificateAuthorityConfigurationWithAccounts {
            inner: CertificateAuthorityConfiguration {
                name: "Fake CA".to_string(),
                identifier: "fake".to_string(),
                acme_directory: test_url(),
                public: false,
                testing: false,
                default: false,
                trusted_roots: vec![],
            },
            accounts: vec![AccountConfiguration {
                name: "Fake Account".to_string(),
                identifier: "fake".to_string(),
                key_file: PathBuf::from("testdata/account.key"),
                url: test_url().join("fake-account")?,
            }],
        };
        // SAFETY: Directory has 'static lifetime
        unsafe {
            faux::when!(mock_client.get_directory).then_unchecked_return(fake_directory);
        }
        let mut mock_resolver = Resolver::faux();
        faux::when!(mock_resolver.resolve_cname_chain).then(Ok);
        let resolver = Arc::new(mock_resolver);
        let issuer = AcmeIssuer::try_new(fake_config, resolver)?;
        issuer.override_client(mock_client)?;
        Ok(issuer)
    }

    fn fake_cert() -> ParsedX509Certificate {
        let not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        let not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(24);
        ParsedX509Certificate {
            serial: BigUint::default(),
            subject: "My Cert".to_string(),
            issuer: "My Issuer".to_string(),
            validity: Validity {
                not_before,
                not_after,
            },
            subject_alternative_names: vec![],
            acme_renewal_identifier: Some(AcmeRenewalIdentifier::new(&[0xDE, 0xAD], &[0xBE, 0xEF])),
            subject_public_key_sha256: [0x00; 32],
        }
    }

    #[tokio::test]
    async fn test_issue_with_cached_authz() -> Result<(), Error> {
        let order_url = test_url().join("cached-auth-order")?;
        let fresh_order = Ok((
            order_url.clone(),
            create_order(OrderStatus::Ready, vec![], None, None),
        ));
        let finalized_order = Ok(create_order(
            OrderStatus::Valid,
            vec![],
            None,
            Some(test_url().join("get-cert")?),
        ));
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.new_order)
            .once()
            .then_return(fresh_order);
        faux::when!(mock_client.finalize_order)
            .once()
            .then_return(finalized_order);
        faux::when!(mock_client.download_certificate(_, test_url().join("get-cert")?))
            .once()
            .then_return(certificate);
        let issuer = setup_fake_issuer(mock_client)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                None,
                None,
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn test_issue_with_single_authz() -> Result<(), Error> {
        let fake_order_url = Url::parse("https://fake.invalid/order")?;
        let fake_authz_url = Url::parse("https://fake.invalid/authz")?;
        let fake_challenge_url = Url::parse("https://fake.invalid/challenge")?;
        let fake_cert_url = Url::parse("https://fake.invalid/cert")?;
        let fresh_order = Ok((
            fake_order_url.clone(),
            create_order(
                OrderStatus::Pending,
                vec![fake_authz_url.clone()],
                None,
                None,
            ),
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
        let ready_order = Ok(create_order(
            OrderStatus::Ready,
            vec![fake_authz_url.clone()],
            None,
            None,
        ));
        let finalized_order = Ok(create_order(
            OrderStatus::Valid,
            vec![fake_authz_url.clone()],
            None,
            Some(fake_cert_url.clone()),
        ));
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.new_order)
            .once()
            .then_return(fresh_order);
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
        let issuer = setup_fake_issuer(mock_client)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                None,
                None,
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn test_issue_with_ari_replaces() -> Result<(), Error> {
        let order_url = test_url().join("cached-auth-order")?;
        let fresh_order = Ok((
            order_url.clone(),
            create_order(OrderStatus::Ready, vec![], None, None),
        ));
        let finalized_order = Ok(create_order(
            OrderStatus::Valid,
            vec![],
            None,
            Some(test_url().join("get-cert")?),
        ));
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;
        let new_order_request = NewOrderRequest {
            identifiers: vec![Identifier::from_str("example.com")?.into()],
            not_before: None,
            not_after: None,
            replaces: Some(AcmeRenewalIdentifier::new(&[0xDE, 0xAD], &[0xBE, 0xEF])),
            profile: None,
        };
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.new_order(_, new_order_request))
            .once()
            .then_return(fresh_order);
        faux::when!(mock_client.finalize_order)
            .once()
            .then_return(finalized_order);
        faux::when!(mock_client.download_certificate(_, test_url().join("get-cert")?))
            .once()
            .then_return(certificate);
        let issuer = setup_fake_issuer(mock_client)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                Some(AcmeRenewalIdentifier::new(&[0xDE, 0xAD], &[0xBE, 0xEF])),
                None,
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn test_issue_with_profile() -> Result<(), Error> {
        let order_url = test_url().join("cached-auth-order")?;
        let fresh_order = Ok((
            order_url.clone(),
            create_order(OrderStatus::Ready, vec![], None, None),
        ));
        let finalized_order = Ok(create_order(
            OrderStatus::Valid,
            vec![],
            None,
            Some(test_url().join("get-cert")?),
        ));
        let certificate = Ok(DownloadedCertificate {
            pem: PassthroughBytes::new("Hello, world!".as_bytes().to_vec()),
            alternate_chains: vec![],
        });
        let keypair = new_key(KeyType::Ecdsa(Curve::P256))?.to_rcgen_keypair()?;
        let new_order_request = NewOrderRequest {
            identifiers: vec![Identifier::from_str("example.com")?.into()],
            not_before: None,
            not_after: None,
            replaces: None,
            profile: Some("profile-test".into()),
        };
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.new_order(_, new_order_request))
            .once()
            .then_return(fresh_order);
        faux::when!(mock_client.finalize_order)
            .once()
            .then_return(finalized_order);
        faux::when!(mock_client.download_certificate(_, test_url().join("get-cert")?))
            .once()
            .then_return(certificate);
        let issuer = setup_fake_issuer(mock_client)?;
        let issuer_with_account = issuer.with_account("fake").unwrap();

        let cert = issuer_with_account
            .issue(
                &keypair,
                None,
                vec![Authorizer::new(
                    Identifier::from_str("example.com")?,
                    NullSolver::default(),
                )],
                None,
                Some("profile-test".into()),
            )
            .await?;

        assert_eq!(cert.pem.as_ref(), "Hello, world!".as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_renewal_info() -> anyhow::Result<()> {
        let fake_cert = fake_cert();
        let now_system = SystemTime::now();
        let now_offset = time::OffsetDateTime::now_utc();
        let ari_start = now_offset - time::Duration::seconds(1);
        let ari_end = now_offset + time::Duration::seconds(1);
        let renewal_response = Ok(RenewalResponse {
            retry_after: now_system,
            renewal_info: RenewalInfo {
                suggested_window: SuggestedWindow {
                    start: ari_start,
                    end: ari_end,
                },
                explanation_url: None,
            },
        });
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.get_renewal_info)
            .once()
            .then_return(renewal_response);
        let issuer = setup_fake_issuer(mock_client)?;

        let renewal_info = issuer
            .get_renewal_info("my-cert".to_string(), &fake_cert)
            .await?
            .expect("Must return RenewalInformation");

        assert!(
            renewal_info.renewal_time >= ari_start,
            "Renewal time {} can not be before ARI window start {ari_start}",
            renewal_info.renewal_time
        );
        assert!(
            renewal_info.renewal_time <= ari_end,
            "Renewal time {} can not be after ARI window end {ari_end}",
            renewal_info.renewal_time
        );
        assert_eq!(renewal_info.cert_id, "my-cert");
        assert!(
            renewal_info.fetched_at >= now_offset,
            "fetched_at {} cannot be before test time {now_offset} (did the system clock go backwards during test?)",
            renewal_info.fetched_at
        );
        assert_eq!(
            renewal_info.next_update, now_system,
            "next update should be precisely the not-after value"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_renewal_info_when_ca_does_not_support_ari() -> anyhow::Result<()> {
        let fake_cert = fake_cert();
        let renewal_response = Err(acme::error::Error::FeatureNotSupported);
        let mut mock_client = AcmeClient::faux();
        faux::when!(mock_client.get_renewal_info)
            .once()
            .then_return(renewal_response);
        let issuer = setup_fake_issuer(mock_client)?;

        let renewal_info = issuer
            .get_renewal_info("my-cert".to_string(), &fake_cert)
            .await?;

        assert_eq!(
            renewal_info, None,
            "No RenewalInformation should be returned if the CA does not support the feature"
        );
        Ok(())
    }

    fn setup_issuer_with_profiles() -> anyhow::Result<(HashMap<String, String>, AcmeIssuer)> {
        let mut mock_client = AcmeClient::faux();
        let expected_profiles: HashMap<_, _> = [
            ("first-profile", "this is the first profile"),
            ("second-profile", "https://example.com/second-profile"),
        ]
        .into_iter()
        .map(|(name, description)| (name.to_string(), description.to_string()))
        .collect();
        let directory = Box::new(Directory {
            new_nonce: test_url(),
            new_account: test_url(),
            new_order: test_url(),
            new_authz: None,
            revoke_cert: test_url(),
            key_change: test_url(),
            renewal_info: None,
            meta: Some(Metadata {
                terms_of_service: None,
                website: None,
                caa_identities: vec![],
                external_account_required: false,
                profiles: expected_profiles.clone(),
            }),
        });
        let directory: &'static Directory = Box::leak(directory);
        // SAFETY: lifetime of directory is 'static
        unsafe {
            faux::when!(mock_client.get_directory).then_unchecked_return(directory);
        }
        let resolver = Arc::new(Resolver::new());
        let issuer = AcmeIssuer::try_new(
            CertificateAuthorityConfigurationWithAccounts {
                inner: CertificateAuthorityConfiguration {
                    name: "test".to_string(),
                    identifier: "test".to_string(),
                    acme_directory: test_url(),
                    public: false,
                    testing: false,
                    default: false,
                    trusted_roots: vec![],
                },
                accounts: vec![],
            },
            resolver,
        )?;
        issuer.override_client(mock_client)?;
        Ok((expected_profiles, issuer))
    }

    #[tokio::test]
    async fn test_get_profiles() -> anyhow::Result<()> {
        let (expected_profiles, issuer) = setup_issuer_with_profiles()?;

        let profiles = issuer.get_profiles().await?;

        assert_eq!(profiles, &expected_profiles,);
        Ok(())
    }

    #[tokio::test]
    async fn test_validate_profile() -> anyhow::Result<()> {
        let (expected_profiles, issuer) = setup_issuer_with_profiles()?;

        issuer
            .validate_profile(Some(expected_profiles.keys().next().unwrap()))
            .await
    }

    #[tokio::test]
    async fn test_validate_profile_with_nonexistent_profile() -> anyhow::Result<()> {
        let (_, issuer) = setup_issuer_with_profiles()?;

        issuer
            .validate_profile(Some(&"this-does-not-exist".into()))
            .await
            .expect_err("Profile should not exist, validation should fail");
        Ok(())
    }
}
