use crate::acme::object::{Identifier, InnerChallenge, Token};
use crate::crypto::jws::JsonWebKey;
use anyhow::Error;
use async_trait::async_trait;

pub trait KeyAuthorization {
    fn get_type(&self) -> &str;
    fn get_token(&self) -> &Token;
    fn get_key_authorization(&self, account_key: &JsonWebKey) -> String;
}

impl KeyAuthorization for InnerChallenge {
    fn get_type(&self) -> &str {
        match &self {
            InnerChallenge::Http(_) => "http-01",
            InnerChallenge::Dns(_) => "dns-01",
            InnerChallenge::Alpn(_) => "tls-alpn-01",
            InnerChallenge::Unknown => "unknown challenge type",
        }
    }

    fn get_token(&self) -> &Token {
        match &self {
            InnerChallenge::Http(http) => &http.token,
            InnerChallenge::Dns(dns) => &dns.token,
            InnerChallenge::Alpn(alpn) => &alpn.token,
            InnerChallenge::Unknown => panic!("Unknown challenge cannot be authorized"),
        }
    }

    fn get_key_authorization(&self, account_key: &JsonWebKey) -> String {
        let token = self.get_token();
        get_key_authorization(account_key, token)
    }
}

fn get_key_authorization(key: &JsonWebKey, token: &Token) -> String {
    let thumbprint = key.get_acme_thumbprint();
    format!("{token}.{thumbprint}")
}

#[async_trait]
pub trait ChallengeSolver {
    fn name(&self) -> &'static str;
    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool;
    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error>;
    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Debug, Default, Clone)]
pub struct NullSolver {}

#[async_trait]
impl ChallengeSolver for NullSolver {
    fn name(&self) -> &'static str {
        "null solver"
    }

    fn supports_challenge(&self, _challenge: &InnerChallenge) -> bool {
        true
    }

    async fn deploy_challenge(
        &mut self,
        _jwk: &JsonWebKey,
        _identifier: &Identifier,
        _challenge: InnerChallenge,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        Ok(())
    }
}
