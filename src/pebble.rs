use crate::acme::object::{Identifier, InnerChallenge, Token};
use crate::challenge_solver::KeyAuthorization;
use crate::config::{PebbleHttpSolverConfiguration, SolverConfiguration};
use crate::crypto::jws::JsonWebKey;
use crate::ChallengeSolver;
use anyhow::{bail, Error};
use async_trait::async_trait;
use serde::Serialize;
use std::sync::LazyLock;
use url::Url;

const PEBBLE_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIIJOLbes8sTr4wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMTcx
MjA2MTk0MjEwWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAyNGUyZGIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5WgZNoVJandj43kkLyU50vzCZ
alozvdRo3OFiKoDtmqKPNWRNO2hC9AUNxTDJco51Yc42u/WV3fPbbhSznTiOOVtn
Ajm6iq4I5nZYltGGZetGDOQWr78y2gWY+SG078MuOO2hyDIiKtVc3xiXYA+8Hluu
9F8KbqSS1h55yxZ9b87eKR+B0zu2ahzBCIHKmKWgc6N13l7aDxxY3D6uq8gtJRU0
toumyLbdzGcupVvjbjDP11nl07RESDWBLG1/g3ktJvqIa4BWgU2HMh4rND6y8OD3
Hy3H8MY6CElL+MOCbFJjWqhtOxeFyZZV9q3kYnk9CAuQJKMEGuN4GU6tzhW1AgMB
AAGjRTBDMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAF85v
d40HK1ouDAtWeO1PbnWfGEmC5Xa478s9ddOd9Clvp2McYzNlAFfM7kdcj6xeiNhF
WPIfaGAi/QdURSL/6C1KsVDqlFBlTs9zYfh2g0UXGvJtj1maeih7zxFLvet+fqll
xseM4P9EVJaQxwuK/F78YBt0tCNfivC6JNZMgxKF59h0FBpH70ytUSHXdz7FKwix
Mfn3qEb9BXSk0Q3prNV5sOV3vgjEtB4THfDxSz9z3+DepVnW3vbbqwEbkXdk3j82
2muVldgOUgTwK8eT+XdofVdntzU/kzygSAtAQwLJfn51fS1GvEcYGBc1bDryIqmF
p9BI7gVKtWSZYegicA==
-----END CERTIFICATE-----";

pub fn pebble_root() -> reqwest::Result<reqwest::Certificate> {
    reqwest::Certificate::from_pem(PEBBLE_ROOT_PEM.as_bytes())
}

static PEBBLE_CHALLTESTSRV_BASE_URL: LazyLock<Url> = LazyLock::new(|| Url::parse("http://localhost:8055/").unwrap());

#[derive(Default)]
pub struct ChallengeTestHttpSolver {
    http: reqwest::Client,
    challenge: Option<InnerChallenge>,
}

impl ChallengeTestHttpSolver {
    pub fn from_config(_config: PebbleHttpSolverConfiguration) -> Box<Self> {
        Box::new(Self {
            challenge: None,
            ..Self::default()
        })
    }
}

#[async_trait]
impl ChallengeSolver for ChallengeTestHttpSolver {
    fn long_name(&self) -> &'static str {
        "pebble-challtestsrv http-01 solver"
    }

    fn short_name(&self) -> &'static str {
        "pebble-http"
    }

    fn config(&self) -> SolverConfiguration {
        SolverConfiguration::PebbleHttp(PebbleHttpSolverConfiguration {})
    }

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Http(_))
    }

    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        _identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        let token = challenge.get_token();
        let authorization = challenge.get_key_authorization(jwk);
        let response = self
            .http
            .post(PEBBLE_CHALLTESTSRV_BASE_URL.join("add-http01").unwrap())
            .json(&ChallTestHttpBody {
                token,
                content: Some(authorization),
            })
            .send()
            .await?;
        self.challenge = Some(challenge);
        response.error_for_status()?;
        Ok(())
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        if let Some(challenge) = self.challenge {
            let response = self
                .http
                .post(PEBBLE_CHALLTESTSRV_BASE_URL.join("del-http01").unwrap())
                .json(&ChallTestHttpBody {
                    token: challenge.get_token(),
                    content: None,
                })
                .send()
                .await?;
            response.error_for_status()?;
            Ok(())
        } else {
            bail!("No challenge to cleanup")
        }
    }
}

#[derive(Serialize)]
struct ChallTestHttpBody<'a> {
    token: &'a Token,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}
