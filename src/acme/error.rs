use crate::acme::http::HttpClient;
use crate::acme::object::Identifier;
use crate::crypto::SignatureError;
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;

pub type ProtocolResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Http(reqwest::Error),
    AcmeProblem(Problem),
    ProtocolViolation(&'static str),
    IoError(std::io::Error),
    CryptoFailure(SignatureError),
    DeserializationFailed(serde::de::value::Error),
    RateLimited(RateLimitError),
    TimedOut(&'static str),
    FeatureNotSupported,
}

impl Error {
    pub async fn get_error_from_http(err_response: reqwest::Response) -> Error {
        let retry_after = HttpClient::extract_backoff(&err_response);
        let status = err_response.status();
        if let Ok(problem) = err_response.json::<Problem>().await {
            if problem.is_rate_limit() {
                RateLimitError {
                    problem,
                    retry_after,
                }
                .into()
            } else {
                Error::AcmeProblem(problem)
            }
        } else {
            Error::AcmeProblem(Problem {
                typ: "unknown".to_string(),
                detail: Some(format!("HTTP error: {status}")),
                subproblems: vec![],
            })
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Http(err)
    }
}

impl From<Problem> for Error {
    fn from(err: Problem) -> Error {
        Error::AcmeProblem(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<serde::de::value::Error> for Error {
    fn from(err: serde::de::value::Error) -> Error {
        Error::DeserializationFailed(err)
    }
}

impl From<SignatureError> for Error {
    fn from(err: SignatureError) -> Error {
        Error::CryptoFailure(err)
    }
}

impl From<RateLimitError> for Error {
    fn from(err: RateLimitError) -> Error {
        Error::RateLimited(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::Http(e) => {
                write!(f, "HTTP error: {e}")
            }
            Error::AcmeProblem(e) => {
                write!(f, "The CA reported a problem: {e}")
            }
            Error::ProtocolViolation(e) => write!(f, "ACME protocol specification violated: {e}"),
            Error::IoError(io) => {
                write!(f, "I/O error: {io}")
            }
            Error::CryptoFailure(msg) => {
                write!(f, "error during cryptographic operation: {msg}")
            }
            Error::DeserializationFailed(serde) => {
                write!(f, "parsing server response failed: {serde}")
            }
            Error::RateLimited(rate_limit) => {
                write!(f, "{rate_limit}")
            }
            Error::TimedOut(msg) => {
                write!(f, "timeout: {msg}")
            }
            Error::FeatureNotSupported => {
                write!(f, "The CA does not support the requested feature")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Skip one level (i.e. directly call source on the embedded error)
        // because we already print the higher-level error during Display, so don't duplicate it in the chain.
        match &self {
            Error::Http(e) => e.source(),
            Error::IoError(io) => io.source(),
            Error::DeserializationFailed(serde) => serde.source(),
            Error::CryptoFailure(crypto) => crypto.source(),
            Error::RateLimited(rate_limit) => rate_limit.source(),
            Error::AcmeProblem(_)
            | Error::ProtocolViolation(_)
            | Error::TimedOut(_)
            | Error::FeatureNotSupported => None,
        }
    }
}

pub const ACME_URN: &str = "urn:ietf:params:acme:error:";
pub const ACME_BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
pub const ACME_RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";
pub const ACME_UNAUTHORIZED: &str = "urn:ietf:params:acme:error:unauthorized";
pub const ACME_SERVER_INTERNAL: &str = "urn:ietf:params:acme:error:serverInternal";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: String,
    pub detail: Option<String>,
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl Problem {
    pub fn is_bad_nonce(&self) -> bool {
        self.typ == ACME_BAD_NONCE || self.subproblems.iter().any(Subproblem::is_bad_nonce)
    }

    pub fn is_rate_limit(&self) -> bool {
        self.typ == ACME_RATE_LIMITED || self.subproblems.iter().any(Subproblem::is_rate_limit)
    }

    pub fn is_auth_failure(&self) -> bool {
        // TODO: Consider caa, connection, dns, incorrectResponse, tls as well
        self.typ == ACME_UNAUTHORIZED || self.subproblems.iter().any(Subproblem::is_auth_failure)
    }

    pub fn is_server_failure(&self) -> bool {
        self.typ == ACME_SERVER_INTERNAL
            || self.subproblems.iter().any(Subproblem::is_server_failure)
    }

    pub fn into_result(self) -> Result<(), Error> {
        Err(self.into())
    }
}

impl Display for Problem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let typ = &self.typ;
        if let Some(detail) = &self.detail {
            write!(f, "{detail}")?;
        } else {
            write!(f, "{typ}")?;
        }
        for subproblem in &self.subproblems {
            write!(f, "\nadditionally, the server reported:\n{subproblem}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Subproblem {
    #[serde(rename = "type")]
    pub typ: String,
    pub detail: Option<String>,
    pub identifier: Option<Identifier>,
}

impl Subproblem {
    pub fn is_bad_nonce(&self) -> bool {
        self.typ == ACME_BAD_NONCE
    }

    pub fn is_rate_limit(&self) -> bool {
        self.typ == ACME_RATE_LIMITED
    }

    pub fn is_auth_failure(&self) -> bool {
        self.typ == ACME_UNAUTHORIZED
    }

    pub fn is_server_failure(&self) -> bool {
        self.typ == ACME_SERVER_INTERNAL
    }
}

impl Display for Subproblem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let typ = &self.typ;
        if let Some(detail) = &self.detail {
            write!(f, "{detail}")?;
        } else {
            write!(f, "{typ}")?;
        }
        if let Some(identifier) = &self.identifier {
            write!(f, "(for identifier: {identifier})")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RateLimitError {
    pub problem: Problem,
    pub retry_after: Option<SystemTime>,
}

impl std::error::Error for RateLimitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl Display for RateLimitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let problem = &self.problem;
        write!(f, "The CA enforced a rate limit: {problem}")?;
        if let Some(retry_after) = self.retry_after {
            let retry_after = time::OffsetDateTime::from(retry_after);
            write!(f, ", and asked to us to retry after: {retry_after}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case::standard(
        r#"{
   "type": "urn:ietf:params:acme:error:userActionRequired",
   "detail": "Terms of service have changed",
   "instance": "https://example.com/acme/agreement/?token=W8Ih3PswD-8"
 }"#, Problem{
    typ: "urn:ietf:params:acme:error:userActionRequired".to_string(),
    detail: Some("Terms of service have changed".to_string()),
    subproblems: vec![],
            })]
    #[case::subproblem(
        r#"{
    "type": "urn:ietf:params:acme:error:malformed",
    "detail": "Some of the identifiers requested were rejected",
    "subproblems": [
        {
            "type": "urn:ietf:params:acme:error:rejectedIdentifier",
            "detail": "This CA will not issue for \"example.net\"",
            "identifier": {
                "type": "dns",
                "value": "example.net"
            }
        }
    ]
}"#, Problem {
            typ: "urn:ietf:params:acme:error:malformed".to_string(),
            detail: Some("Some of the identifiers requested were rejected".to_string()),
            subproblems: vec![Subproblem {
                typ: "urn:ietf:params:acme:error:rejectedIdentifier".to_string(),
                detail: Some(r#"This CA will not issue for "example.net""#.to_string()),
                identifier: Some(Identifier::from_str("example.net").unwrap()),
            }],
            })]
    fn test_deserialize_problem(#[case] json: &str, #[case] expected: Problem) {
        let actual = serde_json::from_str(json).expect("Deserialization must not fail");
        assert_eq!(expected, actual);
    }
}
