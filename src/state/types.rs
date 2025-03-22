pub(super) mod internal {
    use crate::error::{IssueError, IssueResult};
    use strum::FromRepr;
    use time::OffsetDateTime;

    #[derive(Debug, sqlx::FromRow)]
    pub(in crate::state) struct RenewalInformation {
        pub cert_id: String,
        pub fetched_at: OffsetDateTime,
        pub renewal_time: OffsetDateTime,
        pub next_update: OffsetDateTime,
    }

    #[derive(Debug, sqlx::Type, FromRepr, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    #[repr(i32)]
    pub(in crate::state) enum RenewalOutcome {
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
    pub(in crate::state) struct Renewal {
        pub id: i64,
        pub cert_id: String,
        pub outcome: RenewalOutcome,
        pub failure: Option<String>,
        pub timestamp: OffsetDateTime,
    }
}

pub mod external {
    use crate::state::types::internal;
    use std::fmt::Display;
    use time::OffsetDateTime;
    use tracing::warn;

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Renewal {
        pub id: i64,
        pub cert_id: String,
        pub outcome: RenewalOutcome,
        pub timestamp: OffsetDateTime,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, strum::EnumDiscriminants)]
    #[strum_discriminants(derive(Hash))]
    pub enum RenewalOutcome {
        Success,
        RateLimit(String),
        AuthorizationFailure(String),
        CAFailure(String),
        ClientFailure(String),
    }

    impl From<internal::Renewal> for Option<Renewal> {
        fn from(value: internal::Renewal) -> Self {
            let outcome = match value.outcome {
                internal::RenewalOutcome::Unknown => {
                    warn!("Unknown renewal outcome {:?}", value.outcome);
                    None
                }
                internal::RenewalOutcome::Success => Some(RenewalOutcome::Success),
                other => {
                    if let Some(failure) = value.failure {
                        Some(match other {
                            internal::RenewalOutcome::RateLimit => {
                                RenewalOutcome::RateLimit(failure)
                            }
                            internal::RenewalOutcome::AuthorizationFailure => {
                                RenewalOutcome::AuthorizationFailure(failure)
                            }
                            internal::RenewalOutcome::CAFailure => {
                                RenewalOutcome::CAFailure(failure)
                            }
                            internal::RenewalOutcome::ClientFailure => {
                                RenewalOutcome::ClientFailure(failure)
                            }
                            _ => unreachable!(),
                        })
                    } else {
                        warn!("No error message for failure outcome {other:?}");
                        None
                    }
                }
            }?;
            Some(Renewal {
                id: value.id,
                cert_id: value.cert_id,
                outcome,
                timestamp: value.timestamp,
            })
        }
    }

    impl Display for RenewalOutcome {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RenewalOutcome::Success => {
                    write!(f, "Success")
                }
                RenewalOutcome::RateLimit(msg)
                | RenewalOutcome::AuthorizationFailure(msg)
                | RenewalOutcome::CAFailure(msg)
                | RenewalOutcome::ClientFailure(msg) => {
                    write!(f, "{}", msg)
                }
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RenewalInformation {
        pub cert_id: String,
        pub fetched_at: OffsetDateTime,
        pub renewal_time: OffsetDateTime,
        pub next_update: OffsetDateTime,
    }

    impl From<internal::RenewalInformation> for RenewalInformation {
        fn from(value: internal::RenewalInformation) -> Self {
            Self {
                cert_id: value.cert_id,
                fetched_at: value.fetched_at,
                renewal_time: value.renewal_time,
                next_update: value.next_update,
            }
        }
    }

    impl From<RenewalInformation> for internal::RenewalInformation {
        fn from(value: RenewalInformation) -> Self {
            Self {
                cert_id: value.cert_id,
                fetched_at: value.fetched_at,
                renewal_time: value.renewal_time,
                next_update: value.next_update,
            }
        }
    }
}
