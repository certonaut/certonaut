use crate::cert::ParsedX509Certificate;
use crate::{authorizers_from_config, config, crypto, load_certificates_from_file, AcmeIssuerWithAccount, Certonaut};
use anyhow::{anyhow, bail};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::info;

#[allow(clippy::module_name_repetitions)]
pub struct RenewService {
    client: Arc<Certonaut>,
}

impl RenewService {
    pub fn new(client: Certonaut) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let certs = &self.client.cert_list;
        let mut renew_tasks = FuturesUnordered::new();
        for cert_name in certs.keys() {
            let cert_name = cert_name.to_owned();
            let client = self.client.clone();
            renew_tasks.push(tokio::spawn(
                async move { RenewTask::new(cert_name, client).run().await },
            ));
        }

        while let Some(renew_task) = renew_tasks.next().await {
            renew_task??;
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct RenewTask {
    cert_id: String,
    client: Arc<Certonaut>,
}

impl RenewTask {
    pub fn new(cert_name: String, client: Arc<Certonaut>) -> Self {
        Self {
            cert_id: cert_name,
            client,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        // TODO: When non-interactively used, sleep for a random duration before doing anything
        let cert_id = self.cert_id;
        let cert_config = self
            .client
            .cert_list
            .get(&cert_id)
            .ok_or(anyhow!("Certificate {cert_id} not found"))?;
        let cert_name = &cert_config.display_name;
        let certificates =
            load_certificates_from_file(config::certificate_directory(&cert_id).join("fullchain.pem"), Some(1))?;

        let issuer = self
            .client
            .get_issuer_with_account(&cert_config.ca_identifier, &cert_config.account_identifier)?;
        if let Some(leaf) = certificates.first() {
            let renew_in = Self::renew_in(&issuer, leaf).await;
            if renew_in > Duration::from_secs(300) {
                info!("Certificate {cert_name} is not due for renewal for {renew_in:?}");
                return Ok(());
            }
            tokio::time::sleep(renew_in).await;
            // TODO: Reuse key if requested
            let new_key = crypto::asymmetric::new_key(cert_config.key_type)?.to_rcgen_keypair()?;
            // TODO: Remember cert lifetime if set
            let authorizers = authorizers_from_config(cert_config.clone())?;
            let renewed = issuer.issue(&new_key, None, authorizers).await?;
            config::save_certificate_and_config(&cert_id, cert_config, &new_key, &renewed)?;
        } else {
            // TODO: Gracefully handle
            bail!("Certificate {cert_name} fullchain.pem does not contain any X.509 certificate");
        }
        Ok(())
    }

    async fn renew_in(issuer: &AcmeIssuerWithAccount<'_>, cert: &ParsedX509Certificate) -> Duration {
        // TODO: Check ARI first, if available
        // Fallback to 2/3 parsing
        let now = OffsetDateTime::now_utc();
        let not_after = cert.validity.not_after.to_datetime();
        if now >= not_after {
            Duration::ZERO
        } else {
            // TODO: Fix possible underflow panics
            let total_lifetime = not_after - cert.validity.not_before.to_datetime();
            let remaining_lifetime = not_after - now;
            if (total_lifetime / 3) > remaining_lifetime {
                Duration::ZERO
            } else {
                Duration::try_from((total_lifetime / 3) - remaining_lifetime).unwrap_or(Duration::ZERO)
            }
        }
    }
}
