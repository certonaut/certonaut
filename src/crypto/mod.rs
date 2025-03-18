pub mod asymmetric;
pub mod jws;

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
