use crate::crypto::jws::{JsonWebKey, ProtectedHeader, EMPTY_PAYLOAD};
use crate::crypto::signing::KeyPair;
use crate::protocol::error::ProtocolError;
use crate::protocol::error::ProtocolResult;
use crate::protocol::http::{HttpClient, RelationLink};
use crate::protocol::object::{
    Account, AccountRequest, Authorization, Challenge, ChallengeStatus, Directory, EmptyObject,
    FinalizeRequest, NewOrderRequest, Nonce, Order, OrderStatus,
};
use crate::util::serde_helper::PassthroughBytes;
use anyhow::{anyhow, bail};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::CertificateSigningRequest;
use reqwest::StatusCode;
use serde::de::value::BytesDeserializer;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::any::{Any, TypeId};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use url::Url;

/// The maximum number of retries we do, per request
const MAX_RETRIES: usize = 3;
/// The default time we wait between retries, if a retry is needed
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_secs(3);
/// The maximum amount of time we're willing to wait in between retries
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(2 * 60);
/// Maximum time we wait for the server to progress in the state machine
const MAX_POLL_DURATION: Duration = Duration::from_secs(5 * 60);

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

    pub fn with_http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub async fn try_build(self) -> ProtocolResult<AcmeClient> {
        AcmeClient::try_new(self).await
    }
}

pub struct AcmeClient {
    http_client: HttpClient,
    directory: Directory,
    nonce_pool: Mutex<VecDeque<Nonce>>,
}

impl AcmeClient {
    async fn try_new(builder: AcmeClientBuilder) -> ProtocolResult<Self> {
        let http_client = builder
            .http_client
            .ok_or_else(HttpClient::try_new)
            .or_else(|e| e)?;
        // TODO: Retry this or prefer fast fail when directory is invalid?
        let directory_response = http_client.get(builder.server_url).await?;
        let directory = match directory_response.status() {
            StatusCode::OK => directory_response.json().await?,
            _ => return Err(ProtocolError::get_error_from_http(directory_response).await),
        };
        Ok(Self {
            http_client,
            directory,
            nonce_pool: Mutex::new(Default::default()),
        })
    }

    fn try_store_nonce(&self, maybe_nonce: Option<Nonce>) {
        if let Some(nonce) = maybe_nonce {
            self.nonce_pool.lock().unwrap().push_back(nonce);
        }
    }

    async fn post_with_retry<T: Serialize, R: DeserializeOwned + 'static>(
        &self,
        target_url: &Url,
        key: &JsonWebKey,
        payload: Option<&T>,
    ) -> anyhow::Result<AcmeResponse<R>> {
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
            let response = self.http_client.post(target_url.clone(), &signed).await?;
            let backoff = HttpClient::extract_backoff(&response).unwrap_or(DEFAULT_RETRY_BACKOFF);
            let new_nonce = HttpClient::extract_nonce(&response);
            let links = HttpClient::extract_relation_links(&response);
            let location = HttpClient::extract_location(&response);
            let status = response.status();
            match status {
                StatusCode::OK | StatusCode::CREATED => {
                    // Weird hack: The ACME protocol uses JSON for every request and response, except
                    // for downloading a certificate. To avoid unnecessary redundancy, we always
                    // deserialize JSON here, except if the caller requests a PassthroughBytes
                    // struct, where we just pass the received bytes as-is.
                    // This condition is resolved at compile-time, depending on the generic.
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
                        body,
                    };
                    return Ok(response);
                }
                _ => {
                    last_error = ProtocolError::get_error_from_http(response).await;
                    if let ProtocolError::AcmeProblem(problem) = &last_error {
                        if problem.is_bad_nonce() {
                            header.nonce = new_nonce.ok_or(ProtocolError::ProtocolViolation(
                                "Server did not provide a Replay-Nonce on a badNonce error",
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
                            // TODO Return separate ratelimit error, to allow caller decision when to retry
                            bail!("TODO: Rate limits!");
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
            let backoff = if backoff > MAX_RETRY_BACKOFF {
                MAX_RETRY_BACKOFF
            } else {
                backoff
            };
            tokio::time::sleep(backoff).await;
            header.nonce = self.get_nonce().await?;
        }
        Err(last_error.into())
    }

    pub async fn get_nonce(&self) -> ProtocolResult<Nonce> {
        let mut last_error;
        let mut retry = 0;
        loop {
            let pooled_nonce = self.nonce_pool.lock().unwrap().pop_front();
            if let Some(pooled_nonce) = pooled_nonce {
                return Ok(pooled_nonce);
            }

            // Ask ACME server for new nonce, retrying if necessary
            let response = self
                .http_client
                .head(self.directory.new_nonce.clone())
                .await?;
            if let Some(nonce) = HttpClient::extract_nonce(&response) {
                return Ok(nonce);
            }

            let backoff = HttpClient::extract_backoff(&response)
                .map(|backoff| {
                    if backoff > MAX_RETRY_BACKOFF {
                        MAX_RETRY_BACKOFF
                    } else {
                        backoff
                    }
                })
                .unwrap_or(DEFAULT_RETRY_BACKOFF);
            last_error = ProtocolError::get_error_from_http(response).await;
            retry += 1;
            if retry > MAX_RETRIES {
                break;
            }
            tokio::time::sleep(backoff).await;
        }
        Err(last_error)
    }

    pub fn get_directory(&self) -> &Directory {
        &self.directory
    }

    pub async fn register_account(
        &self,
        options: AccountRegisterOptions,
    ) -> anyhow::Result<(JsonWebKey, Url, Account)> {
        let jwk = JsonWebKey::new(options.key);
        let target_url = &self.get_directory().new_account;
        let payload = AccountRequest {
            contact: options.contact,
            terms_of_service_agreed: options.terms_of_service_agreed,
            external_account_binding: None,
        };
        let response = self
            .post_with_retry(target_url, &jwk, Some(&payload))
            .await?;
        let account_url = response.location.ok_or(anyhow!(
            "ACME server did not provide an account URL for created account"
        ))?;
        let created_account = response.body;
        let account_key = jwk.into_existing(account_url.clone());
        Ok((account_key, account_url, created_account))
    }

    pub async fn new_order(
        &self,
        account_key: &JsonWebKey,
        request: &NewOrderRequest,
    ) -> anyhow::Result<(Url, Order)> {
        let target_url = &self.get_directory().new_order;
        let response = self
            .post_with_retry(target_url, account_key, Some(request))
            .await?;
        let order_url = response.location.ok_or(anyhow!(
            "ACME server did not provide an order URL for created order"
        ))?;
        let order = response.body;
        Ok((order_url, order))
    }

    pub async fn get_order(
        &self,
        account_key: &JsonWebKey,
        order_url: &Url,
    ) -> anyhow::Result<Order> {
        let response = self
            .post_with_retry(order_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn get_authorization(
        &self,
        account_key: &JsonWebKey,
        authz_url: &Url,
    ) -> anyhow::Result<Authorization> {
        let response = self
            .post_with_retry(authz_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn get_challenge(
        &self,
        account_key: &JsonWebKey,
        challenge_url: &Url,
    ) -> anyhow::Result<Challenge> {
        let response = self
            .post_with_retry(challenge_url, account_key, EMPTY_PAYLOAD)
            .await?;
        Ok(response.body)
    }

    pub async fn download_certificate(
        &self,
        account_key: &JsonWebKey,
        certificate_url: &Url,
    ) -> anyhow::Result<DownloadedCertificate> {
        let response = self
            .post_with_retry(&certificate_url, account_key, EMPTY_PAYLOAD)
            .await?;
        if !response.status.is_success() {
            return Err(anyhow!("downloading certificate failed"));
        }
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

    pub async fn validate_challenge(
        &self,
        account_key: &JsonWebKey,
        challenge_url: &Url,
    ) -> anyhow::Result<Challenge> {
        // TODO: if already valid, returns error
        let response = self
            .post_with_retry(challenge_url, account_key, Some(&EmptyObject {}))
            .await?;
        let mut challenge: Challenge = response.body;
        let deadline = Instant::now() + MAX_POLL_DURATION;
        while Instant::now() < deadline {
            match challenge.status {
                ChallengeStatus::Pending => {
                    // Challenge should not be in pending after submission, but let's wait anyway
                }
                ChallengeStatus::Processing => {
                    if let Some(err) = challenge.error {
                        // TODO: Some ACME servers retry challenges - both automatically
                        // and client-initiated. How to handle this?
                        // return Err(anyhow!(err));
                    }
                }
                ChallengeStatus::Valid => {
                    return Ok(challenge);
                }
                ChallengeStatus::Invalid => {
                    return if let Some(err) = challenge.error {
                        // TODO: Error types
                        Err(anyhow!(err))
                    } else {
                        Err(anyhow!("Generic error"))
                    };
                }
            }
            tokio::time::sleep(DEFAULT_RETRY_BACKOFF).await;
            challenge = self.get_challenge(account_key, challenge_url).await?;
        }
        // Challenge never reached acceptable state
        // TODO: Err or Ok?
        Ok(challenge)
    }

    pub async fn finalize_order(
        &self,
        account_key: &JsonWebKey,
        order: &Order,
        csr: &CertificateSigningRequest,
    ) -> anyhow::Result<Order> {
        let request = FinalizeRequest {
            csr: BASE64_URL_SAFE_NO_PAD.encode(csr.der()),
        };
        let response = self
            .post_with_retry(&order.finalize, account_key, Some(&request))
            .await?;
        let order_url = response.location.ok_or(anyhow!(
            "Server did not provide an order URL upon finalizing"
        ))?;
        let deadline = Instant::now() + MAX_POLL_DURATION;
        let mut order: Order = response.body;
        while Instant::now() < deadline {
            match order.status {
                OrderStatus::Pending => {
                    // TODO: Not all authorizations fulfilled
                }
                OrderStatus::Ready => {
                    // Makes no sense after submitting the CSR, but wait anyway
                }
                OrderStatus::Processing => {
                    // Just wait
                }
                OrderStatus::Valid => {
                    return Ok(order);
                }
                OrderStatus::Invalid => {
                    return if let Some(err) = order.error {
                        // TODO: Error types
                        Err(anyhow!(err))
                    } else {
                        Err(anyhow!("Generic error"))
                    };
                }
            }
            tokio::time::sleep(DEFAULT_RETRY_BACKOFF).await;
            order = self.get_order(account_key, &order_url).await?;
        }
        Ok(order)
    }
}

#[derive(Debug)]
pub struct AcmeResponse<T: DeserializeOwned> {
    pub status: StatusCode,
    pub location: Option<Url>,
    pub links: Vec<RelationLink>,
    pub body: T,
}

#[derive(Debug)]
pub struct AccountRegisterOptions {
    pub key: KeyPair,
    pub contact: Vec<Url>,
    pub terms_of_service_agreed: Option<bool>,
}

#[derive(Debug)]
pub struct DownloadedCertificate {
    pub pem: PassthroughBytes,
    pub alternate_chains: Vec<Url>,
}

// TODO: tests with mock
