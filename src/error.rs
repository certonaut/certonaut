use crate::acme;
use crate::acme::error::{Error as AcmeError, Error};
use std::backtrace::BacktraceStatus;
use std::fmt::{Debug, Formatter};

pub type IssueResult<T> = Result<T, IssueError>;

pub enum IssueError {
    ClientFailure(anyhow::Error),
    RateLimited(anyhow::Error),
    CAFailure(anyhow::Error),
    AuthFailure(anyhow::Error),
}

impl IssueError {
    /// Returns this error message formatted in a standardized way, to be suitable for saving in a database.
    /// The formatting is currently anyhow's "pretty" debug layout, but without any backtraces (even if backtraces are
    /// enabled).
    pub fn to_database_string(&self) -> String {
        // There is an unfortunate misfeature in anyhow: If RUST_BACKTRACE env is set, we cannot
        // suppress anyhow from printing the captured backtrace in errors without disabling pretty-printing.

        // Therefore, hack the backtrace out of the generated string. This is quite slow, but so is capturing backtraces
        // on errors.
        let mut error_string = format!("Error: {self}");
        match self {
            IssueError::ClientFailure(err)
            | IssueError::RateLimited(err)
            | IssueError::CAFailure(err)
            | IssueError::AuthFailure(err) => {
                if err.backtrace().status() == BacktraceStatus::Captured {
                    if let Some(index) = error_string.find("Stack backtrace:") {
                        error_string = error_string[..index].trim().to_string();
                    };
                }
            }
        };
        error_string
    }
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
                Error::ProtocolViolation(_) => IssueError::CAFailure(err),
                Error::AcmeProblem(problem) => (problem.clone(), err).into(),
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

impl From<(acme::error::Problem, anyhow::Error)> for IssueError {
    fn from((problem, err): (acme::error::Problem, anyhow::Error)) -> Self {
        if problem.is_rate_limit() {
            IssueError::RateLimited(err)
        } else if problem.is_server_failure() {
            IssueError::CAFailure(err)
        } else if problem.is_auth_failure() {
            IssueError::AuthFailure(err)
        } else {
            IssueError::ClientFailure(err)
        }
    }
}

pub trait IssueContext<T> {
    fn client_failure(self) -> IssueResult<T>;
    fn ca_failure(self) -> IssueResult<T>;
}

impl<T> IssueContext<T> for anyhow::Error {
    fn client_failure(self) -> IssueResult<T> {
        Err(IssueError::ClientFailure(self))
    }

    fn ca_failure(self) -> IssueResult<T> {
        Err(IssueError::CAFailure(self))
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
}
