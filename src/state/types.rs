use crate::error::{IssueError, IssueResult};
use strum::FromRepr;
use time::OffsetDateTime;

#[derive(Debug, sqlx::FromRow)]
struct Ari {
    fetched_at: OffsetDateTime,
    result: String,
    next_update: OffsetDateTime,
}

#[derive(Debug, sqlx::Type)]
#[repr(i32)]
#[derive(FromRepr)]
pub enum RenewalOutcome {
    Unknown = -1,
    Success = 0,
    RateLimit = 1,
    AuthorizationFailure = 2,
    CAFailure = 3,
    ClientFailure = 4,
}

impl<T> From<&IssueResult<T>> for RenewalOutcome {
    fn from(value: &IssueResult<T>) -> Self {
        match value {
            Ok(_) => RenewalOutcome::Success,
            Err(IssueError::RateLimited(_)) => RenewalOutcome::RateLimit,
            Err(IssueError::AuthFailure(_)) => RenewalOutcome::AuthorizationFailure,
            Err(IssueError::CAFailure(_)) => RenewalOutcome::CAFailure,
            Err(IssueError::ClientFailure(_)) => RenewalOutcome::ClientFailure,
        }
    }
}

impl From<i64> for RenewalOutcome {
    fn from(value: i64) -> Self {
        i32::try_from(value)
            .ok()
            .map_or(RenewalOutcome::Unknown, Into::into)
    }
}

impl From<i32> for RenewalOutcome {
    fn from(value: i32) -> Self {
        RenewalOutcome::from_repr(value).unwrap_or(RenewalOutcome::Unknown)
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct Renewal {
    pub id: i64,
    pub cert_id: String,
    pub outcome: RenewalOutcome,
    pub failure: Option<String>,
    pub timestamp: OffsetDateTime,
}
