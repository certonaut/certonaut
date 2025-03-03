use crate::challenge_solver::HttpChallengeParameters;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub fn is_supported() -> bool {
    false
}

#[allow(clippy::unused_async)]
pub async fn deploy_challenge(
    _http_challenge_parameters: HttpChallengeParameters,
    _cancellation_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    Ok(tokio::spawn(async { Ok(()) }))
}
