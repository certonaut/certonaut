use crate::Certonaut;
use crate::cert::ParsedX509Certificate;
use crate::config::{ConfigBackend, config_directory};
use crate::state::types::external::{RenewalOutcome, RenewalOutcomeDiscriminants};
use crate::time::humanize_duration;
use crate::{AcmeIssuerWithAccount, state};
use anyhow::{Context, anyhow, bail};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use itertools::Itertools;
use rand::random_range;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Sub;
use std::sync::Arc;
use strum::IntoDiscriminant;
use time::{Duration, OffsetDateTime};
use tracing::{debug, error, info, warn};

const MAX_RANDOM_SLEEP_BEFORE_RENEW_SECONDS: i64 = Duration::minutes(10).whole_seconds();
const MAX_SHORT_SLEEP_BEFORE_RENEW_SECONDS: i64 = Duration::minutes(5).whole_seconds();

#[allow(clippy::module_name_repetitions)]
pub struct RenewService<CB> {
    interactive: bool,
    client: Arc<Certonaut<CB>>,
}

impl<CB: ConfigBackend + Send + Sync + 'static> RenewService<CB> {
    pub fn new(client: Certonaut<CB>, interactive: bool) -> Self {
        Self {
            interactive,
            client: Arc::new(client),
        }
    }

    pub async fn renew_single_cert(
        self,
        cert_name: String,
        renew_early: bool,
    ) -> anyhow::Result<()> {
        let mut config = RenewConfig::new(self.interactive);
        if renew_early {
            config.renew_early = true;
            config.sleep = false;
        }
        let certs = [(cert_name, config)].into();
        self.run(certs).await
    }

    pub async fn renew_all(self) -> anyhow::Result<()> {
        let certs = self
            .client
            .certificates
            .keys()
            .cloned()
            .map(|cert_name| (cert_name, RenewConfig::new(self.interactive)))
            .collect();
        self.run(certs).await
    }

    async fn run(self, renew_configs: HashMap<String, RenewConfig>) -> anyhow::Result<()> {
        let lock = state::RenewalLock::exclusive_lock(config_directory())
            .await
            .context("Failed to acquire exclusive file lock for renewal")?;
        let mut renew_tasks = FuturesUnordered::new();
        for (cert_name, renew_config) in renew_configs.into_iter() {
            let cert_name = cert_name.to_owned();
            let client = self.client.clone();
            renew_tasks.push(tokio::spawn(async move {
                RenewTask::new(renew_config, cert_name.clone(), client)
                    .run()
                    .await
                    .context(format!("Renewing certificate {cert_name}"))
            }));
        }

        let mut errors = Vec::new();
        while let Some(renew_task) = renew_tasks.next().await {
            if let Err(e) = renew_task.context("Renew task panicked").and_then(|e| e) {
                eprintln!("Error: {e:?}");
                eprintln!();
                errors.push(e);
            }
        }

        if !errors.is_empty() {
            // Repeat the error messages one more time at the end, because the original message may be hidden among
            // other log output.
            eprintln!("=== Error Summary ===");
            let error_len = errors.len();
            for error in errors {
                eprintln!("Error: {error:?}");
                eprintln!();
            }
            if error_len == 1 {
                bail!("1 attempted renewal failed. See the error message above for details.");
            }
            bail!(
                "{error_len} attempted renewals failed. See the error messages above for details."
            );
        }
        drop(lock);
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
struct RenewConfig {
    _interactive: bool,
    renew_early: bool,
    sleep: bool,
}

impl Default for RenewConfig {
    fn default() -> Self {
        Self {
            _interactive: false,
            renew_early: false,
            sleep: true,
        }
    }
}

impl RenewConfig {
    pub fn new(interactive: bool) -> Self {
        Self {
            _interactive: interactive,
            sleep: !interactive,
            ..Self::default()
        }
    }
}

#[allow(clippy::module_name_repetitions)]
struct RenewTask<CB: ConfigBackend> {
    cert_id: String,
    client: Arc<Certonaut<CB>>,
    config: RenewConfig,
}

impl<CB: ConfigBackend> RenewTask<CB> {
    pub fn new(config: RenewConfig, cert_name: String, client: Arc<Certonaut<CB>>) -> Self {
        Self {
            cert_id: cert_name,
            client,
            config,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        if self.config.sleep {
            let random_sleep_seconds = random_range(0..MAX_RANDOM_SLEEP_BEFORE_RENEW_SECONDS);
            let random_sleep = Duration::seconds(random_sleep_seconds);
            info!(
                "Sleeping for {} before checking certificate {}",
                humanize_duration(random_sleep),
                self.cert_id
            );
            tokio::time::sleep(
                random_sleep
                    .try_into()
                    .unwrap_or(std::time::Duration::from_secs(
                        MAX_RANDOM_SLEEP_BEFORE_RENEW_SECONDS as u64,
                    )),
            )
            .await;
        }
        let cert_id = &self.cert_id;
        let cert_config = self
            .client
            .certificates
            .get(cert_id)
            .ok_or(anyhow!("Certificate {cert_id} not found"))?;
        let cert_name = &cert_config.display_name;
        let certificates = self
            .client
            .config
            .load_certificate_files(cert_id, Some(1))?;

        let issuer = self
            .client
            .get_issuer_with_account(&cert_config.ca_identifier, &cert_config.account_identifier)?;
        if let Some(leaf) = certificates.first() {
            let renew_in = if self.config.renew_early {
                Duration::ZERO
            } else {
                self.renew_in(&issuer, leaf).await
            };
            let renew_in_humanized = humanize_duration(renew_in);
            if renew_in > Duration::new(MAX_SHORT_SLEEP_BEFORE_RENEW_SECONDS, 0) {
                info!("Certificate {cert_name} is not due for renewal for {renew_in_humanized}");
                return Ok(());
            }
            match self.decide_noninteractive_renewal().await? {
                BackoffDecision::NoBackoff => {}
                BackoffDecision::Backoff(reason) => {
                    if issuer.config.testing {
                        warn!(
                            "Certificate {cert_name} has repeated renewal failures. Trying to renew anyway since {} is a test CA",
                            { &issuer.config.name }
                        );
                        info!(
                            "If this were not a test CA, then we would not renew because of: {reason}"
                        );
                    } else {
                        warn!(
                            "Not renewing certificate {cert_name} at this time because of: {reason}"
                        );
                        return Ok(());
                    }
                }
            }
            info!("Certificate {cert_name} will be renewed in {renew_in_humanized}");
            tokio::time::sleep(renew_in.try_into().unwrap_or(std::time::Duration::ZERO)).await;
            self.client
                .renew_certificate(&issuer, cert_id, cert_config, leaf)
                .await?;
            self.client
                .install_certificate(cert_id, cert_config)
                .await
                .context(format!("Installing certificate {cert_name}"))?;
        } else {
            // TODO: Gracefully handle
            bail!("Certificate {cert_name} fullchain.pem does not contain any X.509 certificate");
        }
        Ok(())
    }

    /// Decide whether renewal can be attempted now, based on previous renewal history.
    /// Specifically, this code will suggest backoff if recent renewals failed repeatedly.
    async fn decide_noninteractive_renewal(&self) -> anyhow::Result<BackoffDecision> {
        if self.config.renew_early {
            // User asked to renew now. Honor the user's request.
            return Ok(BackoffDecision::NoBackoff);
        }

        // Events older than the cutoff are not considered for decision-making
        let cutoff = OffsetDateTime::now_utc().sub(Duration::days(7));
        let recent_renewals = self
            .client
            .database
            .get_latest_renewals(&self.cert_id, cutoff)
            .await?;
        let last_success = recent_renewals
            .iter()
            .rev()
            .find(|r| r.outcome == RenewalOutcome::Success);
        let last_failure = recent_renewals.iter().rev().find(|r| {
            r.outcome != RenewalOutcome::Success && last_success.is_none_or(|s| r.id > s.id)
        });

        if let Some(last_failure) = last_failure {
            let time_since_last_failure = OffsetDateTime::now_utc() - last_failure.timestamp;

            // All failures since the last success (or all since the cutoff)
            let recent_failures = recent_renewals.iter().filter(|r| {
                r.outcome != RenewalOutcome::Success && last_success.is_none_or(|s| r.id > s.id)
            });

            let mut failure_buckets = HashMap::new();

            for failure in recent_failures {
                let discriminant = failure.outcome.discriminant();
                let mut occurrences = failure_buckets
                    .get(&discriminant)
                    .copied()
                    .unwrap_or(0usize);
                occurrences += 1;
                failure_buckets.insert(failure.outcome.discriminant(), occurrences);
            }

            if let Some((failure_type, _)) = failure_buckets
                .into_iter()
                .sorted_by(|(_, left), (_, right)| std::cmp::Ord::cmp(right, left))
                .find(|(_, count)| *count >= 3)
            {
                // We keep failing with the same problem. Reduce attempts to no more than twice a day.
                if time_since_last_failure < Duration::hours(12) {
                    let next_retry = Duration::hours(12) - time_since_last_failure;
                    return Ok(BackoffDecision::Backoff(BackoffReason {
                        next_retry,
                        failure_type,
                        last_failure: last_failure.outcome.to_string(),
                    }));
                }
                return Ok(BackoffDecision::NoBackoff);
            }

            Ok(BackoffDecision::NoBackoff)
        } else {
            // No recent failures
            Ok(BackoffDecision::NoBackoff)
        }
    }

    async fn renew_in(
        &self,
        issuer: &AcmeIssuerWithAccount<'_>,
        cert: &ParsedX509Certificate,
    ) -> Duration {
        // As per ARI draft, we must not query ARI for expired certificates, so check that first.
        let now = OffsetDateTime::now_utc();
        let not_after = cert.validity.not_after;
        if now >= not_after {
            let serial = &cert.serial;
            debug!("Certificate with serial {serial} expired, suggesting renewal now");
            return Duration::ZERO;
        }

        // Check ARI next (both cached in database, and online if needed)
        let renewal_info = match self
            .client
            .database
            .get_renewal_information(&self.cert_id)
            .await
        {
            Ok(Some(stored_renewal_info)) => {
                if now >= stored_renewal_info.next_update {
                    // Try updating ARI
                    self.client
                        .try_fetch_and_store_ari(issuer, self.cert_id.clone(), cert)
                        .await
                } else {
                    // Stored is still current
                    Some(stored_renewal_info)
                }
            }
            Ok(None) => {
                // Never successfully fetched ARI for this cert
                self.client
                    .try_fetch_and_store_ari(issuer, self.cert_id.clone(), cert)
                    .await
            }
            Err(e) => {
                error!(
                    "Failed to fetch latest ACME Renewal Information result from local database: {e:#}"
                );
                None
            }
        };

        if let Some(renewal_info) = renewal_info {
            debug!(
                "ARI determined random renewal time @ {}",
                renewal_info.renewal_time
            );
            if now > renewal_info.renewal_time {
                debug!("ARI determined time is in the past, suggesting renewal now");
                return Duration::ZERO;
            }
            let time_until_renew = renewal_info.renewal_time - now;
            let next_update = renewal_info.next_update;
            let fetched_at = renewal_info.fetched_at;
            debug!(
                "ARI suggested renewal time is in {time_until_renew}, next ARI update scheduled for {next_update}. This window was queried @ {fetched_at}"
            );
            return time_until_renew;
        }

        // Fallback to 2/3 parsing
        // TODO: Fix possible underflow panics
        let total_lifetime = not_after - cert.validity.not_before;
        let remaining_lifetime = not_after - now;
        let one_third_lifetime = total_lifetime / 3;
        let time_until_renew = remaining_lifetime - one_third_lifetime;
        if time_until_renew < Duration::ZERO {
            Duration::ZERO
        } else {
            time_until_renew
        }
    }
}

#[derive(Debug, Clone)]
enum BackoffDecision {
    NoBackoff,
    Backoff(BackoffReason),
}

#[derive(Debug, Clone)]
struct BackoffReason {
    next_retry: Duration,
    failure_type: RenewalOutcomeDiscriminants,
    last_failure: String,
}

impl Display for BackoffReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let time = humanize_duration(self.next_retry);
        match self.failure_type {
            RenewalOutcomeDiscriminants::Success => {
                write!(f, "Next retry in {time}.")
            }
            RenewalOutcomeDiscriminants::RateLimit => {
                write!(f, "The CA enforced a rate limit. Next retry in {time}.")
            }
            RenewalOutcomeDiscriminants::AuthorizationFailure => {
                write!(
                    f,
                    "Too many authorization failures. This indicates a configuration problem on your side. Next retry in {time}."
                )
            }
            RenewalOutcomeDiscriminants::CAFailure => {
                write!(
                    f,
                    "The Certificate Authority seems to be experiencing an issue. Next retry in {time}."
                )
            }
            RenewalOutcomeDiscriminants::ClientFailure => {
                write!(f, "Too many client-side errors. Next retry in {time}.")
            }
        }?;
        write!(f, " The last recorded failure was:\n{}", self.last_failure)
    }
}
