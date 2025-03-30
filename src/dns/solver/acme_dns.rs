use crate::Identifier;
use crate::acme::object::InnerChallenge;
use crate::challenge_solver::ChallengeSolver;
use crate::crypto::jws::JsonWebKey;
use anyhow::Error;
use async_trait::async_trait;

pub struct AcmeDnsSolver {}

#[async_trait]
impl ChallengeSolver for AcmeDnsSolver {
    fn long_name(&self) -> &'static str {
        "ACME-DNS challenge solver"
    }

    fn short_name(&self) -> &'static str {
        "acme-dns"
    }

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Dns(_))
    }

    async fn deploy_challenge(
        &mut self,
        _jwk: &JsonWebKey,
        _identifier: &Identifier,
        _challenge: InnerChallenge,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        todo!()
    }
}
