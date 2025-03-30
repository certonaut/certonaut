use crate::Identifier;
use crate::acme::object::InnerChallenge;
use crate::challenge_solver::{ChallengeSolver, HttpChallengeParameters};
use crate::config::MagicHttpSolverConfiguration;
use crate::crypto::jws::JsonWebKey;
use anyhow::{Error, bail};
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
    pub fn try_from_config(config: MagicHttpSolverConfiguration) -> anyhow::Result<Box<Self>> {
        if !is_supported() {
            bail!("MagicHttpSolver is not supported on this system");
        }

        Ok(Box::new(if let Some(port) = config.validation_port {
            MagicHttpSolver::new(port)
        } else {
            MagicHttpSolver::default()
        }))
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

    fn supports_challenge(&self, challenge: &InnerChallenge) -> bool {
        matches!(challenge, InnerChallenge::Http(_))
    }

    async fn deploy_challenge(
        &mut self,
        jwk: &JsonWebKey,
        _identifier: &Identifier,
        challenge: InnerChallenge,
    ) -> Result<(), Error> {
        if let InnerChallenge::Http(http_challenge) = challenge {
            let params = HttpChallengeParameters {
                token: http_challenge.get_token().clone(),
                key_authorization: http_challenge.get_key_authorization(jwk),
                challenge_port: self.challenge_port,
            };
            let cancellation_token = CancellationToken::new();
            let task = deploy_challenge(params, cancellation_token.clone()).await?;
            self.inner = Some(MagicHttpSolverChallengeData {
                task,
                cancellation: cancellation_token.drop_guard(),
            });
            Ok(())
        } else {
            bail!("Unsupported challenge type {}", challenge.get_type())
        }
    }

    async fn cleanup_challenge(self: Box<Self>) -> Result<(), Error> {
        match self.inner {
            Some(data) => {
                // Cancel the task
                drop(data.cancellation);
                Ok(data.task.await??)
            }
            None => {
                bail!("No challenge to cleanup")
            }
        }
    }
}

// TODO: Cache result
// TODO: Also show reason why not
pub fn is_supported() -> bool {
    imp::is_supported()
}

async fn deploy_challenge(
    http_challenge_parameters: HttpChallengeParameters,
    cancellation_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    imp::deploy_challenge(http_challenge_parameters, cancellation_token).await
}
