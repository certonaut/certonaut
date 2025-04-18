use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod asymmetric;
pub mod jws;
pub mod symmetric;

pub const SHA256_LENGTH: usize = 32;

/// Computes the SHA2-256 digest over the provided byte slice.
///
/// # Panics
///
/// If the hashing engine encounters a catastrophic problem (such as the earth no longer being round)
pub fn sha256(input: &[u8]) -> [u8; SHA256_LENGTH] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input)
        .as_ref()
        .try_into()
        .expect("SHA256 returned a hash with size != 32")
}

#[derive(Debug)]
pub enum SignatureError {
    Serialization(serde_json::Error),
    SignatureGeneration(&'static str),
    EncodingFailed(&'static str),
}

impl Error for SignatureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            SignatureError::Serialization(ser) => ser.source(),
            SignatureError::EncodingFailed(_) | SignatureError::SignatureGeneration(_) => None,
        }
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            SignatureError::Serialization(e) => write!(f, "JSON encoding failed: {e}"),
            SignatureError::EncodingFailed(msg) | SignatureError::SignatureGeneration(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl From<serde_json::Error> for SignatureError {
    fn from(e: serde_json::Error) -> Self {
        SignatureError::Serialization(e)
    }
}
