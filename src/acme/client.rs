use crate::acme::error::ProtocolResult;
use crate::acme::error::{Error, RateLimitError};
use crate::acme::http::HttpClient;
use crate::acme::http::RelationLink;
use crate::acme::object::{
    Account, AccountRequest, AcmeRenewalIdentifier, Authorization, Challenge, ChallengeStatus,
    Deactivation, Directory, EmptyObject, FinalizeRequest, NewOrderRequest, Nonce, Order,
    OrderStatus, RenewalInfo, Revocation, RevocationReason,
};
use crate::crypto::asymmetric::KeyPair;
use crate::crypto::jws::{EMPTY_PAYLOAD, ExternalAccountBinding, JsonWebKey, ProtectedHeader};
use crate::url::Url;
use crate::util::serde_helper::PassthroughBytes;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use parking_lot::Mutex;
use rcgen::CertificateSigningRequest;
use reqwest::StatusCode;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::de::value::BytesDeserializer;
use std::any::TypeId;
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::time::{Duration, SystemTime};
use tokio::time::Instant;
use tracing::{debug, warn};

/// The maximum number of retries we do, per request
const MAX_RETRIES: usize = 3;
/// The default time we wait between retries, if a retry is needed
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_secs(3);
/// The maximum amount of time we're willing to wait in between retries
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(2 * 60);
/// Maximum time we wait for the server to progress in the state machine
const MAX_POLL_DURATION: Duration = Duration::from_secs(5 * 60);

/// `AcmeClientBuilder` allows to instantiate new `AcmeClient` instances, optionally with extra configuration
pub struct AcmeClientBuilder {
    server_url: Url,
    http_client: Option<HttpClient>,
}

impl AcmeClientBuilder {
    pub fn new(acme_server_url: Url) -> AcmeClientBuilder {
        Self {
            server_url: acme_server_url,
            http_client: None,
        }
    }

    /// Optionally, use a custom `HttpClient` for HTTP requests instead of a default one.
    #[must_use]
    pub fn with_http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Try to create a new `AcmeClient` with the current configuration. This will validate the configuration and
    /// fetch the ACME directory from the CA. If this fails, an error is returned.
    pub async fn try_build(self) -> ProtocolResult<AcmeClient> {
        AcmeClient::try_new(self).await
    }
}

#[cfg_attr(test, faux::create)]
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct AcmeClient {
    http_client: HttpClient,
    directory: Directory,
    nonce_pool: Mutex<VecDeque<Nonce>>,
}

// Separate impl block due to faux limitations
impl AcmeClient {
    async fn try_new(builder: AcmeClientBuilder) -> ProtocolResult<Self> {
        let http_client = builder
            .http_client
            .ok_or_else(HttpClient::try_new)
            .or_else(|e| e)?;
        let directory_response = http_client
            .get_with_retry(&builder.server_url, MAX_RETRIES, DEFAULT_RETRY_BACKOFF)
            .await?;
        let directory = match directory_response.status() {
            StatusCode::OK => directory_response.json().await?,
            _ => return Err(Error::get_error_from_http(directory_response).await),
        };
        Ok(Self::new(
            http_client,
            directory,
            Mutex::new(VecDeque::new()),
        ))
    }
}

// Main impl block
#[cfg_attr(test, faux::methods)]
impl AcmeClient {
    // helper for faux
    fn new(
        http_client: HttpClient,
        directory: Directory,
        nonce_pool: Mutex<VecDeque<Nonce>>,
    ) -> Self {
        Self {
            http_client,
            directory,
            nonce_pool,
        }
    }

    /// Get an unused nonce suitable for use in an ACME-JWS.
    ///
    /// This returns a nonce from the pool if one is available, or requests a new nonce from the ACME CA.
    /// This function implements automatic retries in case of sporadic errors. A returned nonce is guaranteed
    /// not to have been returned previously.
    ///
    /// # Errors
    ///
    /// If no unused nonce could be retrieved from the pool or the ACME CA.
    pub async fn get_nonce(&self) -> ProtocolResult<Nonce> {
        let mut last_error;
        let mut retry = 0;
        loop {
            let pooled_nonce = self.nonce_pool.lock().pop_front();
            if let Some(pooled_nonce) = pooled_nonce {
                return Ok(pooled_nonce);
            }

            // Ask ACME server for new nonce, retrying if necessary
            let response = match self
                .http_client
                .head(self.directory.new_nonce.clone())
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    last_error = err;
                    retry += 1;
                    if retry > MAX_RETRIES {
                        break;
                    }
                    warn!(
                        "Error retrieving nonce from ACME server: {:#}. Retrying...",
                        anyhow::Error::from(last_error)
                    );
                    let backoff = DEFAULT_RETRY_BACKOFF;
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            };
            if let Some(nonce) = HttpClient::extract_nonce(&response) {
                return Ok(nonce);
            }

            let retry_after = HttpClient::extract_backoff(&response);
            last_error = Error::get_error_from_http(response).await;
            retry += 1;
            if retry > MAX_RETRIES {
                break;
            }
            let backoff = backoff_from_retry_after(retry_after);
            tokio::time::sleep(backoff).await;
        }
        Err(last_error)
    }

    fn try_store_nonce(&self, maybe_nonce: Option<Nonce>) {
        if let Some(nonce) = maybe_nonce {
            self.nonce_pool.lock().push_back(nonce);
        }
    }

    async fn post_with_retry<T: Serialize, R: DeserializeOwned + 'static>(
        &self,
        target_url: &Url,
        key: &JsonWebKey,
        payload: Option<&T>,
    ) -> ProtocolResult<AcmeResponse<R>> {
        let mut last_error;
        let mut retry = 0;
        let mut header = ProtectedHeader::new(
            key.get_algorithm(),
            self.get_nonce().await?,
            target_url.clone(),
            key.get_parameters().clone(),
        );
        loop {
            let signed = key.sign(&header, payload)?;
            let response = match self.http_client.post(target_url.clone(), &signed).await {
                Ok(response) => response,
                Err(err) => {
                    last_error = err;
                    retry += 1;
                    if retry > MAX_RETRIES {
                        break;
                    }
                    warn!(
                        "Error sending ACME request: {:#}. Retrying...",
                        anyhow::Error::from(last_error)
                    );
                    let backoff = DEFAULT_RETRY_BACKOFF;
                    tokio::time::sleep(backoff).await;
                    // we probably don't need a new nonce here, but reusing nonces feels very wrong security-wise
                    header.nonce = self.get_nonce().await?;
                    continue;
                }
            };

            let retry_after = HttpClient::extract_backoff(&response);
            let new_nonce = HttpClient::extract_nonce(&response);
            let links = HttpClient::extract_relation_links(&response);
            let location = HttpClient::extract_location(&response);
            let status = response.status();

            // TODO: Size limit on all responses, for DoS safety?
            match status {
                StatusCode::OK | StatusCode::CREATED => {
                    self.try_store_nonce(new_nonce);
                    // Weird hack: The ACME protocol uses JSON for every (POST) request and response,
                    // except when downloading a certificate. To avoid unnecessary redundancy, we always
                    // deserialize JSON here, except if the caller requests a PassthroughBytes
                    // struct, where we just pass the received bytes as-is.
                    // This condition is resolved at compile-time, depending on `R`.
                    let body: R = if TypeId::of::<R>() == TypeId::of::<PassthroughBytes>() {
                        let bytes = response.bytes().await?;
                        let deserializer =
                            BytesDeserializer::<'_, serde::de::value::Error>::new(&bytes);
                        R::deserialize(deserializer)?
                    } else {
                        response.json().await?
                    };
                    let response = AcmeResponse {
                        status,
                        location,
                        links,
                        retry_after,
                        body,
                    };
                    return Ok(response);
                }
                _ => {
                    last_error = Error::get_error_from_http(response).await;
                    if let Error::AcmeProblem(problem) = &last_error {
                        if problem.is_bad_nonce() {
                            header.nonce = new_nonce.ok_or(Error::ProtocolViolation(
                                "Server did not provide a (valid) Replay-Nonce on a badNonce error",
                            ))?;
                            retry += 1;
                            if retry > MAX_RETRIES {
                                break;
                            }
                            // Immediate retry with new nonce
                            continue;
                        }
                        self.try_store_nonce(new_nonce);

                        if problem.is_rate_limit() {
                            // TODO: Retry without returning if the rate limit is lifted within a short time
                            return Err(RateLimitError {
                                problem: problem.clone(),
                                retry_after,
                            }
                            .into());
                        }
                    } else {
                        self.try_store_nonce(new_nonce);
                    }
                }
            }
            retry += 1;
            // Give up if the request doesn't seem salvageable
            if status.is_client_error() || retry > MAX_RETRIES {
                break;
            }
            let backoff = backoff_from_retry_after(retry_after);
            tokio::time::sleep(backoff).await;
            header.nonce = self.get_nonce().await?;
        }
        Err(last_error)
    }

    /// Get the ACME directory resource.
    ///
    /// This is cached, so subsequent calls will return the same directory.
    pub fn get_directory(&self) -> &Directory {
        &self.directory
    }

    /// Register a new account at the CA.
    ///
    /// # Returns
    ///
    /// - A `JsonWebKey` that can sign ACME requests for the newly created account
    /// - The account URL
    /// - The created account resource
    ///
    /// # Errors
    ///
    /// If a network error occurs, or the CA refused account creation.
    pub async fn register_account(
        &self,
        options: AccountRegisterOptions,
    ) -> ProtocolResult<(JsonWebKey, Url, Account)> {
        let jwk = JsonWebKey::new(options.key);
        let target_url = &self.get_directory().new_account;
        let eab = if let Some(eab) = options.external_account_binding {
            Some(eab.sign(target_url.clone(), &jwk)?)
        } else {
            None
        };
        let payload = AccountRequest {
            contact: options.contact,
            terms_of_service_agreed: options.terms_of_service_agreed,
            external_account_binding: eab,
            only_return_existing: None,
        };
        let response = self
            .post_with_retry(target_url, &jwk, Some(&payload))
            .await?;
        let account_url = response.location.ok_or(Error::ProtocolViolation(
            "ACME server did not provide an account URL for created account",
        ))?;
        let created_account = response.body;
        let account_key = jwk.into_existing(account_url.clone());
        Ok((account_key, account_url, created_account))
    }

    /// Fetch the account resource belonging to both the `account_key` and `account_url`
    pub async fn fetch_account(
        &self,
        account_key: &JsonWebKey,
        account_url: &Url,
    ) -> ProtocolResult<Account> {
        let response = self
            .post_with_retry(account_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    /// Fetch the account resource belonging to the `account_key`, when the `account_url` is not known
    pub async fn fetch_unknown_account(
        &self,
        account_key: KeyPair,
    ) -> ProtocolResult<(JsonWebKey, Url, Account)> {
        let jwk = JsonWebKey::new(account_key);
        let target_url = &self.get_directory().new_account;
        let payload = AccountRequest {
            contact: Vec::new(),
            terms_of_service_agreed: None,
            external_account_binding: None,
            only_return_existing: Some(true),
        };
        let response = self
            .post_with_retry(target_url, &jwk, Some(&payload))
            .await?;
        let account_url = response.location.ok_or(Error::ProtocolViolation(
            "ACME server did not provide an account URL for created account",
        ))?;
        let created_account = response.body;
        let account_key = jwk.into_existing(account_url.clone());
        Ok((account_key, account_url, created_account))
    }

    pub async fn new_order(
        &self,
        account_key: &JsonWebKey,
        request: &NewOrderRequest,
    ) -> ProtocolResult<(Url, Order)> {
        let target_url = &self.get_directory().new_order;
        let response = self
            .post_with_retry(target_url, account_key, Some(request))
            .await?;
        let order_url = response.location.ok_or(Error::ProtocolViolation(
            "ACME server did not provide an order URL for created order",
        ))?;
        let order = response.body;
        Ok((order_url, order))
    }

    pub async fn get_order(
        &self,
        account_key: &JsonWebKey,
        order_url: &Url,
    ) -> ProtocolResult<Order> {
        let response = self
            .post_with_retry(order_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn get_authorization(
        &self,
        account_key: &JsonWebKey,
        authz_url: &Url,
    ) -> ProtocolResult<Authorization> {
        let response = self
            .post_with_retry(authz_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn get_challenge(
        &self,
        account_key: &JsonWebKey,
        challenge_url: &Url,
    ) -> ProtocolResult<Challenge> {
        let response = self
            .post_with_retry(challenge_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn download_certificate(
        &self,
        account_key: &JsonWebKey,
        certificate_url: &Url,
    ) -> ProtocolResult<DownloadedCertificate> {
        let response = self
            .post_with_retry(certificate_url, account_key, EMPTY_PAYLOAD)
            .await?;
        let alternate_chains = response
            .links
            .into_iter()
            .filter(|link| link.relation == "alternate")
            .map(|link| link.url)
            .collect();
        let pem = response.body;
        Ok(DownloadedCertificate {
            pem,
            alternate_chains,
        })
    }

    /// Ask the ACME server to attempt validation of the challenge identified by `challenge_url`.
    ///
    /// Note: It is an error to attempt validation of a challenge that is not in a suitable state (e.g. not pending/processing).
    /// This function does not check the state of the challenge before submitting the validation attempt.
    ///
    /// # Returns
    ///
    /// The validated challenge, or an error if validation failed.
    pub async fn validate_challenge(
        &self,
        account_key: &JsonWebKey,
        challenge_url: &Url,
    ) -> ProtocolResult<Challenge> {
        let response = self
            .post_with_retry(challenge_url, account_key, Some(&EmptyObject {}))
            .await?;
        let mut retry_after = response.retry_after;
        let mut challenge: Challenge = response.body;
        let deadline = Instant::now() + MAX_POLL_DURATION;
        let mut last_error = None;
        while Instant::now() < deadline {
            match challenge.status {
                ChallengeStatus::Pending => {
                    // Challenge should not be in pending after submission, but let's wait anyway
                }
                ChallengeStatus::Processing => {
                    if let Some(err) = challenge.error {
                        // If the ACME server reports processing and an error,
                        // it is still retrying. Remember the error in case we give up,
                        // but keep polling to see if the server-initiated retry works.
                        last_error = Some(err.into());
                    }
                }
                ChallengeStatus::Valid => {
                    return Ok(challenge);
                }
                ChallengeStatus::Invalid => {
                    return if let Some(err) = challenge.error {
                        Err(err.into())
                    } else {
                        Err(Error::ProtocolViolation(
                            "challenge is invalid, but CA did not provide an error message why",
                        ))
                    };
                }
            }
            let backoff = backoff_from_retry_after(retry_after);
            tokio::time::sleep(backoff).await;
            let response = self
                .post_with_retry(challenge_url, account_key, EMPTY_PAYLOAD)
                .await?;
            challenge = response.body;
            retry_after = response.retry_after;
        }
        // Challenge never reached acceptable state
        Err(last_error
            .unwrap_or_else(|| Error::TimedOut("Timed out waiting for challenge validation")))
    }

    pub async fn finalize_order(
        &self,
        account_key: &JsonWebKey,
        order: Order,
        order_url: &Url,
        csr: &CertificateSigningRequest,
    ) -> ProtocolResult<Order> {
        match order.status {
            OrderStatus::Ready => {
                let request = FinalizeRequest {
                    csr: BASE64_URL_SAFE_NO_PAD.encode(csr.der()),
                };
                let response = self
                    .post_with_retry(&order.finalize, account_key, Some(&request))
                    .await?;
                let order_url = response.location.unwrap_or_else(|| order_url.clone());
                let retry_after = response.retry_after;
                let backoff = backoff_from_retry_after(retry_after);
                tokio::time::sleep(backoff).await;
                self.poll_finalized_order(account_key, response.body, &order_url)
                    .await
            }
            OrderStatus::Processing => {
                self.poll_finalized_order(account_key, order, order_url)
                    .await
            }
            OrderStatus::Valid => Ok(order),
            _ => Err(Error::ProtocolViolation(
                "Order with status that is neither ready nor processing cannot be finalized",
            )),
        }
    }

    async fn poll_finalized_order(
        &self,
        account_key: &JsonWebKey,
        mut order: Order,
        order_url: &Url,
    ) -> ProtocolResult<Order> {
        let deadline = Instant::now() + MAX_POLL_DURATION;
        while Instant::now() < deadline {
            match order.status {
                OrderStatus::Pending => {
                    return Err(Error::ProtocolViolation(
                        "CA flipped the order status unexpectedly: Order was ready/processing, but is now reset to pending",
                    ));
                }
                OrderStatus::Ready => {
                    return Err(Error::ProtocolViolation(
                        "CA flipped the order status unexpectedly: Order was ready/processing, but is now reset to ready",
                    ));
                }
                OrderStatus::Processing => {
                    // Just wait
                    tokio::time::sleep(DEFAULT_RETRY_BACKOFF).await;
                    order = self.get_order(account_key, order_url).await?;
                }
                OrderStatus::Valid => {
                    return Ok(order);
                }
                OrderStatus::Invalid => {
                    return if let Some(err) = order.error {
                        Err(err.into())
                    } else {
                        Err(Error::ProtocolViolation(
                            "Order is invalid, but CA did not provide an error message why",
                        ))
                    };
                }
            }
        }
        Err(Error::TimedOut("Timed out waiting for order finalization"))
    }

    pub async fn deactivate_account(
        &self,
        account_key: &JsonWebKey,
        account_url: &Url,
    ) -> ProtocolResult<Account> {
        let response = self
            .post_with_retry(account_url, account_key, Some(&Deactivation::new()))
            .await?;
        Ok(response.body)
    }

    pub async fn deactivate_authorization(
        &self,
        account_key: &JsonWebKey,
        authz_url: &Url,
    ) -> ProtocolResult<Authorization> {
        let response = self
            .post_with_retry(authz_url, account_key, Some(&Deactivation::new()))
            .await?;
        Ok(response.body)
    }

    /// Request revocation of a certificate by the CA.
    ///
    /// # Arguments
    ///
    /// - `revocation_key` - The key with which to revoke the certificate. This can be either an ACME Account Key
    ///   (that was used to issue the certificate), or alternatively also the private key of the certificate.
    ///   Some CAs require that a specific key is used for a particular revocation scenario, e.g. the certificate
    ///   key may be required for the `RevocationReason::KeyCompromise` reason code.
    /// - `certificate_der` - The certificate's bytes in DER encoding
    /// - `reason` - Optional reason for revocation to be signalled to the CA. This may change the semantics of the revocation.
    ///   Not all CAs support all reason codes.
    pub async fn revoke_certificate(
        &self,
        revocation_key: &JsonWebKey,
        certificate_der: &[u8],
        reason: Option<RevocationReason>,
    ) -> ProtocolResult<()> {
        let revoke_url = &self.get_directory().revoke_cert;
        let payload = Revocation {
            certificate: BASE64_URL_SAFE_NO_PAD.encode(certificate_der),
            reason,
        };
        // This is a bit annoying: The revocation success response is not JSON, but an entirely empty body. To avoid
        // the parser tripping on an empty body, request an unparsed response instead (which we will then just ignore).
        let _response: AcmeResponse<PassthroughBytes> = self
            .post_with_retry(revoke_url, revocation_key, Some(&payload))
            .await?;
        Ok(())
    }

    #[allow(clippy::missing_panics_doc)]
    pub async fn get_renewal_info(
        &self,
        identifier: &AcmeRenewalIdentifier,
    ) -> ProtocolResult<RenewalResponse> {
        if let Some(ari_base) = &self.get_directory().renewal_info {
            let mut ari_base = ari_base.clone();
            let ari_path = ari_base.path();
            if !ari_path.ends_with('/') {
                // Ensure trailing slash for correct join behavior
                let new_path = format!("{}/", ari_path);
                ari_base.set_path(&new_path);
            }
            let fetch_url = ari_base
                .join(&identifier.to_string())
                .expect("BUG: URL joining with AcmeRenewalIdentifier must never fail");
            debug!("Retrieving ARI from ACME server @ {fetch_url}");
            let response = self
                .http_client
                .get_with_retry(&fetch_url, MAX_RETRIES, DEFAULT_RETRY_BACKOFF)
                .await?;
            let retry_after = HttpClient::extract_backoff(&response);
            let retry_after = retry_after.map_or(
                SystemTime::now() + time::Duration::hours(6),
                |retry_after| {
                    // Check for excessively large or small values
                    if let Ok(backoff) = retry_after.duration_since(SystemTime::now()) {
                        if backoff > time::Duration::hours(24) {
                            // backoff is more than a full day, clamp to one day
                            SystemTime::now() + time::Duration::hours(24)
                        } else if backoff < time::Duration::minutes(1) {
                            // time is < 1 minute, clamp to one minute
                            SystemTime::now() + time::Duration::minutes(1)
                        } else {
                            // no clamping
                            retry_after
                        }
                    } else {
                        // now() is in the future, clamp to one minute
                        SystemTime::now() + time::Duration::minutes(1)
                    }
                },
            );

            match response.status() {
                StatusCode::OK => {
                    let renewal_info = response.json().await?;
                    Ok(RenewalResponse {
                        retry_after,
                        renewal_info,
                    })
                }
                _ => {
                    // TODO: What if there's a rate limit error here?
                    Err(Error::get_error_from_http(response).await)
                }
            }
        } else {
            Err(Error::FeatureNotSupported)
        }
    }
}

#[derive(Debug)]
pub struct AcmeResponse<T: DeserializeOwned> {
    pub status: StatusCode,
    pub location: Option<Url>,
    pub links: Vec<RelationLink>,
    pub retry_after: Option<SystemTime>,
    pub body: T,
}

#[derive(Debug)]
pub struct AccountRegisterOptions {
    pub key: KeyPair,
    pub contact: Vec<Url>,
    pub terms_of_service_agreed: Option<bool>,
    pub external_account_binding: Option<ExternalAccountBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedCertificate {
    pub pem: PassthroughBytes,
    pub alternate_chains: Vec<Url>,
}

#[derive(Debug, Clone)]
pub struct RenewalResponse {
    pub retry_after: SystemTime,
    pub renewal_info: RenewalInfo,
}

impl Display for RenewalResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Retry-After: {} | {:?}",
            time::OffsetDateTime::from(self.retry_after),
            self.renewal_info.suggested_window
        )?;
        match &self.renewal_info.explanation_url {
            None => {
                write!(f, " | Explanation URL: None")
            }
            Some(url) => {
                write!(f, " | Explanation URL: {url}")
            }
        }
    }
}

fn backoff_from_retry_after(retry_after: Option<SystemTime>) -> Duration {
    retry_after
        .and_then(|date| date.duration_since(SystemTime::now()).ok())
        .map_or(DEFAULT_RETRY_BACKOFF, |backoff| {
            if backoff > MAX_RETRY_BACKOFF {
                MAX_RETRY_BACKOFF
            } else {
                backoff
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::http::test_helper::{AbsoluteUrl, MockJsonResponse};
    use crate::acme::object::SuggestedWindow;
    use crate::crypto::jws::FlatJsonWebSignature;
    use mockito::{Mock, ServerGuard};
    use serde_json::json;
    use std::fs::File;
    use time::macros::datetime;

    const NONCE_VALUE: &str = "notActuallyRandom";
    const ACCOUNT_URL: &str = "http://localhost/account-url";

    trait JoseMatcher {
        fn match_jose<F>(self, request_matcher: F) -> Self
        where
            F: Fn(FlatJsonWebSignature) -> bool + Send + Sync + 'static;
    }

    impl JoseMatcher for Mock {
        fn match_jose<F>(self, request_matcher: F) -> Self
        where
            F: Fn(FlatJsonWebSignature) -> bool + Send + Sync + 'static,
        {
            self.match_request(move |request| {
                let body = request
                    .body()
                    .expect("Must have a request body when matching");
                let Ok(json) = serde_json::de::from_slice::<serde_json::Value>(body) else {
                    return false;
                };
                let Some(json) = json.as_object() else {
                    return false;
                };
                let Some(header) = json.get("protected").and_then(|value| value.as_str()) else {
                    return false;
                };
                let Some(payload) = json.get("payload").and_then(|value| value.as_str()) else {
                    return false;
                };
                let Some(signature) = json.get("signature").and_then(|value| value.as_str()) else {
                    return false;
                };
                let jws = FlatJsonWebSignature::new_test_values(header, payload, signature);
                request_matcher(jws)
            })
        }
    }

    async fn create_acme_server() -> ServerGuard {
        let mut server = mockito::Server::new_async().await;
        let directory = Directory {
            new_nonce: server.absolute_url("/new-nonce"),
            new_account: server.absolute_url("/new-account"),
            new_order: server.absolute_url("/new-order"),
            new_authz: None,
            revoke_cert: server.absolute_url("/revoke-cert"),
            key_change: server.absolute_url("/key-change"),
            renewal_info: Some(server.absolute_url("/renewal-info")),
            meta: None,
        };
        server
            .mock("GET", "/")
            .with_json_body(&directory)
            .create_async()
            .await;
        server
    }

    fn test_jwk() -> JsonWebKey {
        JsonWebKey::new_existing(
            KeyPair::load_from_disk(File::open("testdata/keys/account.key").unwrap()).unwrap(),
            Url::parse(ACCOUNT_URL).unwrap(),
        )
    }

    async fn setup_nonces(server: &mut ServerGuard, num_nonces: usize) -> Mock {
        server
            .mock("HEAD", "/new-nonce")
            .expect(num_nonces)
            .with_status(200)
            .with_header("Replay-Nonce", NONCE_VALUE)
            .create_async()
            .await
    }

    async fn build_acme_client(server: &ServerGuard) -> AcmeClient {
        AcmeClientBuilder::new(server.absolute_url(String::new().as_str()))
            .try_build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_try_new() {
        let server = create_acme_server().await;
        let _ = build_acme_client(&server).await;
    }

    #[tokio::test]
    async fn test_new_nonce() {
        let mut server = create_acme_server().await;
        let nonces = setup_nonces(&mut server, 1).await;
        let client = build_acme_client(&server).await;
        let nonce = client.get_nonce().await.unwrap();
        nonces.assert_async().await;
        assert_eq!(nonce.to_string(), NONCE_VALUE);
    }

    #[tokio::test]
    async fn test_new_nonce_with_retry() {
        let mut server = create_acme_server().await;
        server
            .mock("HEAD", "/new-nonce")
            .expect(1)
            .with_status(200)
            .with_header("Replay-Nonce", NONCE_VALUE)
            .create_async()
            .await;
        server
            .mock("HEAD", "/new-nonce")
            .expect(1)
            .with_status(429)
            .with_header("Retry-After", "1")
            .create_async()
            .await;
        server
            .mock("HEAD", "/new-nonce")
            .expect(1)
            .with_status(429)
            .with_header("Retry-After", "1")
            .create_async()
            .await;
        let client = build_acme_client(&server).await;
        let nonce = client.get_nonce().await.unwrap();
        assert_eq!(nonce.to_string(), NONCE_VALUE);
    }

    #[tokio::test]
    async fn test_new_nonce_when_unreachable_errors() {
        let mut server = create_acme_server().await;
        let nonce_mock = server
            .mock("HEAD", "/new-nonce")
            .expect(4)
            .with_status(429)
            .with_header("Retry-After", "1")
            .create_async()
            .await;
        let client = build_acme_client(&server).await;
        let err = client.get_nonce().await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "The CA reported a problem: HTTP error: 429 Too Many Requests"
        );
        nonce_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_post_with_retry_when_bad_nonce_retries() {
        fn match_nonce(jws: &FlatJsonWebSignature, expected_nonce: &str) -> bool {
            let Ok(header) = jws.header_json() else {
                return false;
            };
            let Some(nonce) = header.get("nonce").and_then(|value| value.as_str()) else {
                return false;
            };
            nonce == expected_nonce
        }

        let bad_nonce_error = json!({
         "type": "urn:ietf:params:acme:error:badNonce",
        })
        .to_string();
        let mut server = create_acme_server().await;
        let first_nonce = setup_nonces(&mut server, 1).await;
        server
            .mock("POST", "/retry-test")
            .match_jose(|jws| match_nonce(&jws, NONCE_VALUE))
            .with_status(400)
            .with_header("Replay-Nonce", "ThisNonceIsNotValid")
            .with_header("Content-Type", "application/problem+json")
            .with_body(&bad_nonce_error)
            .create_async()
            .await;
        server
            .mock("POST", "/retry-test")
            .match_jose(|jws| match_nonce(&jws, "ThisNonceIsNotValid"))
            .with_status(400)
            .with_header("Replay-Nonce", "NonceIsNotValidEither-Sorry")
            .with_header("Content-Type", "application/problem+json")
            .with_body(&bad_nonce_error)
            .create_async()
            .await;
        server
            .mock("POST", "/retry-test")
            .match_jose(|jws| match_nonce(&jws, "NonceIsNotValidEither-Sorry"))
            .with_status(400)
            .with_header("Replay-Nonce", "ThisNonceIsValid")
            .with_header("Content-Type", "application/problem+json")
            .with_body(&bad_nonce_error)
            .create_async()
            .await;
        server
            .mock("POST", "/retry-test")
            .match_jose(|jws| match_nonce(&jws, "ThisNonceIsValid"))
            .with_status(200)
            .with_body("null")
            .create_async()
            .await;
        let client = build_acme_client(&server).await;
        let jwk = test_jwk();
        let response: AcmeResponse<()> = client
            .post_with_retry(&server.absolute_url("/retry-test"), &jwk, EMPTY_PAYLOAD)
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        first_nonce.assert_async().await;
    }

    #[test]
    fn test_backoff_from_retry_after_future_time() {
        let future = SystemTime::now() + Duration::from_secs(2);
        let backoff = backoff_from_retry_after(Some(future));
        assert!(backoff.as_secs_f64() >= 1.0 && backoff.as_secs_f64() <= 2.0);
    }

    #[test]
    fn test_backoff_from_retry_after_nothing() {
        let backoff = backoff_from_retry_after(None);
        assert_eq!(backoff, DEFAULT_RETRY_BACKOFF);
    }

    #[test]
    fn test_backoff_from_retry_after_past_time() {
        let past = SystemTime::now() - Duration::from_secs(2);
        let backoff = backoff_from_retry_after(Some(past));
        assert_eq!(backoff, DEFAULT_RETRY_BACKOFF);
    }

    #[tokio::test]
    async fn test_get_renewal_info() {
        let mut server = create_acme_server().await;
        server
            .mock("GET", "/renewal-info/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
            .expect(1)
            .with_header("Retry-After", "21600")
            .with_json_body(&json!({
              "suggestedWindow": {
                "start": "2025-01-02T04:00:00Z",
                "end": "2025-01-03T04:00:00Z"
              },
              "explanationURL": "https://acme.example.com/docs/ari"
            }))
            .create_async()
            .await;
        let client = build_acme_client(&server).await;
        let identifier = AcmeRenewalIdentifier::new(
            &[
                0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0,
                0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4,
            ],
            &[0x00, 0x87, 0x65, 0x43, 0x21],
        );

        let response = client.get_renewal_info(&identifier).await.unwrap();
        assert_eq!(
            response.renewal_info,
            RenewalInfo {
                suggested_window: SuggestedWindow {
                    start: datetime!(2025-01-02 04:00:00 UTC),
                    end: datetime!(2025-01-03 04:00:00 UTC)
                },
                explanation_url: Some(Url::parse("https://acme.example.com/docs/ari").unwrap())
            },
        );
        let time_delta = response.retry_after - time::OffsetDateTime::now_utc();
        assert!(time_delta >= time::Duration::hours(5) && time_delta <= time::Duration::hours(7));
    }

    #[tokio::test]
    async fn test_revoke_certificate() -> ProtocolResult<()> {
        let mut server = create_acme_server().await;
        let mock = server
            .mock("POST", "/revoke-cert")
            .match_jose(|jws| {
                let Ok(payload) = jws.payload_json() else {
                    return false;
                };
                let Some(payload) = payload.as_object() else {
                    return false;
                };
                let Some(certificate) = payload.get("certificate").and_then(|value| value.as_str())
                else {
                    return false;
                };
                certificate == "3q2-7w"
            })
            .create_async()
            .await;
        let nonce_mock = setup_nonces(&mut server, 1).await;
        let client = build_acme_client(&server).await;
        let jwk = test_jwk();

        client
            .revoke_certificate(&jwk, &[0xDE, 0xAD, 0xBE, 0xEF], None)
            .await?;

        mock.assert_async().await;
        nonce_mock.assert_async().await;
        Ok(())
    }

    // TODO: Other methods
}
