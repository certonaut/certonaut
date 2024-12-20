use crate::acme::object::{Identifier, InnerChallenge};
use crate::challenge_solver::{ChallengeSolver, HttpChallengeParameters, KeyAuthorization};
use crate::config::{MagicHttpSolverConfiguration, SolverConfiguration};
use crate::crypto::jws::JsonWebKey;
use anyhow::{bail, Error};
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

pub const DEFAULT_CHALLENGE_PORT: u16 = 80;

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
#[path = "bpf_proxy.rs"]
mod imp;
#[cfg(not(all(target_os = "linux", feature = "magic-solver")))]
#[path = "noop.rs"]
mod imp;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct MagicHttpSolver {
    challenge_port: u16,
    inner: Option<MagicHttpSolverChallengeData>,
}

impl MagicHttpSolver {
    pub fn new(challenge_port: u16) -> Self {
        Self {
            challenge_port,
            inner: None,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn from_config(config: MagicHttpSolverConfiguration) -> Box<Self> {
        Box::new(if let Some(port) = config.validation_port {
            MagicHttpSolver::new(port)
        } else {
            MagicHttpSolver::default()
        })
    }
}

impl Default for MagicHttpSolver {
    fn default() -> Self {
        Self::new(DEFAULT_CHALLENGE_PORT)
    }
}

#[derive(Debug)]
struct MagicHttpSolverChallengeData {
    task: JoinHandle<anyhow::Result<()>>,
    cancellation: DropGuard,
}

#[async_trait]
impl ChallengeSolver for MagicHttpSolver {
    fn long_name(&self) -> &'static str {
        "magic HTTP-01 solver"
    }

    fn short_name(&self) -> &'static str {
        "magic-http"
    }

    fn config(&self) -> SolverConfiguration {
        let port = if self.challenge_port == DEFAULT_CHALLENGE_PORT {
            None
        } else {
            Some(self.challenge_port)
        };
        SolverConfiguration::MagicHttp(MagicHttpSolverConfiguration { validation_port: port })
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
        let params = HttpChallengeParameters {
            token: challenge.get_token().clone(),
            key_authorization: challenge.get_key_authorization(jwk),
            challenge_port: self.challenge_port,
        };
        let cancellation_token = CancellationToken::new();
        let task = deploy_challenge(params, cancellation_token.clone()).await?;
        self.inner = Some(MagicHttpSolverChallengeData {
            task,
            cancellation: cancellation_token.drop_guard(),
        });
        Ok(())
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        match self.inner {
            Some(data) => {
                // Could also drop the guard, but this is more explicit
                let cancellation = data.cancellation.disarm();
                cancellation.cancel();
                Ok(data.task.await??)
            }
            None => {
                bail!("No challenge to cleanup")
            }
        }
    }
}

pub fn is_supported() -> bool {
    imp::is_supported()
}

async fn deploy_challenge(
    http_challenge_parameters: HttpChallengeParameters,
    cancellation_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    imp::deploy_challenge(http_challenge_parameters, cancellation_token).await
}
