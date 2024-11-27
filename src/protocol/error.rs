use crate::protocol::object::Identifier;
use serde::Deserialize;
use std::fmt::{Display, Formatter};

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug)]
pub enum ProtocolError {
    Http(reqwest::Error),
    #[deprecated(note = "This is a bad error type that should be refactored")]
    Generic(String),
    AcmeProblem(Problem),
    ProtocolViolation(&'static str),
}

impl ProtocolError {
    pub async fn get_error_from_http(err_response: reqwest::Response) -> ProtocolError {
        let status = err_response.status();
        if let Ok(problem) = err_response.json::<Problem>().await {
            ProtocolError::AcmeProblem(problem)
        } else {
            ProtocolError::Generic(format!("HTTP error: {status}"))
        }
    }
}

impl From<reqwest::Error> for ProtocolError {
    fn from(err: reqwest::Error) -> ProtocolError {
        ProtocolError::Http(err)
    }
}

impl From<Problem> for ProtocolError {
    fn from(err: Problem) -> ProtocolError {
        ProtocolError::AcmeProblem(err)
    }
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            ProtocolError::Http(e) => {
                write!(f, "HTTP error: {e}")
            }
            ProtocolError::AcmeProblem(e) => {
                write!(f, "ACME error: {e}")
            }
            ProtocolError::Generic(e) => write!(f, "error: {e}"),
            ProtocolError::ProtocolViolation(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub const ACME_BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
pub const ACME_RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: String,
    pub detail: Option<String>,
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl Problem {
    pub fn is_bad_nonce(&self) -> bool {
        self.typ == ACME_BAD_NONCE
            || self
                .subproblems
                .iter()
                .any(|problem| problem.is_bad_nonce())
    }

    pub fn is_rate_limit(&self) -> bool {
        self.typ == ACME_RATE_LIMITED
            || self
                .subproblems
                .iter()
                .any(|problem| problem.is_rate_limit())
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
            write!(f, "(for identifier:  {identifier})")?;
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
