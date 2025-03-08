use crate::acme;
use crate::acme::error::{Error as AcmeError, Error};
use std::fmt::{Debug, Formatter};

pub type IssueResult<T> = Result<T, IssueError>;

pub enum IssueError {
    ClientFailure(anyhow::Error),
    RateLimited(anyhow::Error),
    CAFailure(anyhow::Error),
    AuthFailure(anyhow::Error),
}

impl std::error::Error for IssueError {}

impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            IssueError::ClientFailure(err)
            | IssueError::RateLimited(err)
            | IssueError::CAFailure(err)
            | IssueError::AuthFailure(err) => std::fmt::Debug::fmt(err, f),
        }
    }
}

impl Debug for IssueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl From<anyhow::Error> for IssueError {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<AcmeError>() {
            Some(inner) => match inner {
                Error::ProtocolViolation(_) | Error::AcmeProblem(_) => IssueError::CAFailure(err),
                Error::IoError(_)
                | Error::CryptoFailure(_)
                | Error::DeserializationFailed(_)
                | Error::Http(_)
                | Error::TimedOut(_) => IssueError::ClientFailure(err),
                Error::RateLimited(_) => IssueError::RateLimited(err),
            },
            None => IssueError::ClientFailure(err),
        }
    }
}

impl From<acme::error::Problem> for IssueError {
    fn from(err: acme::error::Problem) -> Self {
        if err.is_rate_limit() {
            IssueError::RateLimited(AcmeError::from(err).into())
        } else {
            IssueError::CAFailure(AcmeError::from(err).into())
        }
    }
}

pub trait IssueContext<T> {
    fn client_failure(self) -> IssueResult<T>;
    fn ca_failure(self) -> IssueResult<T>;
    fn authentication_failure(self) -> IssueResult<T>;
}

impl<T> IssueContext<T> for anyhow::Error {
    fn client_failure(self) -> IssueResult<T> {
        Err(IssueError::ClientFailure(self))
    }

    fn ca_failure(self) -> IssueResult<T> {
        Err(IssueError::CAFailure(self))
    }

    fn authentication_failure(self) -> IssueResult<T> {
        Err(IssueError::AuthFailure(self))
    }
}

impl<T> IssueContext<T> for Result<T, anyhow::Error> {
    fn client_failure(self) -> IssueResult<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => err.client_failure(),
        }
    }

    fn ca_failure(self) -> IssueResult<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => err.ca_failure(),
        }
    }

    fn authentication_failure(self) -> IssueResult<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => err.authentication_failure(),
        }
    }
}
