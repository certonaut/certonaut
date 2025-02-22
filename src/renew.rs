use crate::cert::ParsedX509Certificate;
use crate::{
    authorizers_from_config, config, crypto, load_certificates_from_file, util, AcmeIssuerWithAccount, Certonaut,
};
use anyhow::{anyhow, bail};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info};

#[allow(clippy::module_name_repetitions)]
pub struct RenewService {
    interactive: bool,
    client: Arc<Certonaut>,
}

impl RenewService {
    pub fn new(client: Certonaut, interactive: bool) -> Self {
        Self {
            interactive,
            client: Arc::new(client),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let certs = &self.client.cert_list;
        let mut renew_tasks = FuturesUnordered::new();
        for cert_name in certs.keys() {
            let cert_name = cert_name.to_owned();
            let client = self.client.clone();
            renew_tasks.push(tokio::spawn(async move {
                RenewTask::new(self.interactive, cert_name, client).run().await
            }));
        }

        while let Some(renew_task) = renew_tasks.next().await {
            renew_task??;
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct RenewTask {
    interactive: bool,
    cert_id: String,
    client: Arc<Certonaut>,
}

impl RenewTask {
    pub fn new(interactive: bool, cert_name: String, client: Arc<Certonaut>) -> Self {
        Self {
            interactive,
            cert_id: cert_name,
            client,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        if !self.interactive {
            // TODO: Sleep for a random duration
        }
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
            let renew_in_humanized = util::humanize_duration(renew_in);
            if renew_in > Duration::new(300, 0) {
                info!("Certificate {cert_name} is not due for renewal for {renew_in_humanized}");
                return Ok(());
            }
            info!("Certificate {cert_name} will be renewed in {renew_in_humanized}");
            tokio::time::sleep(renew_in.try_into().unwrap_or(std::time::Duration::ZERO)).await;
            info!("Renewing certificate {cert_name} at CA {}", issuer.issuer.config.name);
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

    #[allow(clippy::unused_async)]
    async fn renew_in(_issuer: &AcmeIssuerWithAccount<'_>, cert: &ParsedX509Certificate) -> Duration {
        let cert_serial = &cert.serial;
        // TODO: Check ARI first, if available
        // Fallback to 2/3 parsing
        let now = OffsetDateTime::now_utc();
        let not_after = cert.validity.not_after.to_datetime();
        if now >= not_after {
            debug!("Certificate with serial {cert_serial} expired, suggesting renewal now");
            Duration::ZERO
        } else {
            // TODO: Fix possible underflow panics
            let total_lifetime = not_after - cert.validity.not_before.to_datetime();
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
}
