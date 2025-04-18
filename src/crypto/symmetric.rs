use crate::crypto::SignatureError;
use crate::crypto::jws::Algorithm;
use aws_lc_rs::hmac;

#[allow(clippy::module_name_repetitions)]
pub trait SymmetricKeyOperation
where
    Self: Sized,
{
    fn sign(&self, message: &[u8]) -> Result<impl AsRef<[u8]>, SignatureError>;
    fn algorithm(&self) -> Algorithm;
}

#[derive(Debug)]
pub enum MacKey {
    Hmac(HashMacKey),
}

impl MacKey {
    pub fn new_hmac(key: &[u8]) -> Self {
        MacKey::Hmac(HashMacKey::new_with_defaults(key))
    }
}

#[derive(Debug)]
pub struct HashMacKey {
    key: hmac::Key,
}

impl HashMacKey {
    pub fn new_with_defaults(key: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        }
    }

    pub fn hmac_sign(&self, data: &[u8]) -> HmacSignature {
        let tag = hmac::sign(&self.key, data);
        tag.into()
    }
}

impl SymmetricKeyOperation for HashMacKey {
    fn sign(&self, message: &[u8]) -> Result<impl AsRef<[u8]>, SignatureError> {
        Ok(self.hmac_sign(message))
    }

    fn algorithm(&self) -> Algorithm {
        // May want to support multiple algs here in the future - for now, assume everything is HMAC-SHA256
        Algorithm::HmacSha256
    }
}

pub struct HmacSignature {
    inner: hmac::Tag,
}

impl From<hmac::Tag> for HmacSignature {
    fn from(value: hmac::Tag) -> Self {
        Self { inner: value }
    }
}

impl AsRef<[u8]> for HmacSignature {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl SymmetricKeyOperation for MacKey {
    fn sign(&self, message: &[u8]) -> Result<impl AsRef<[u8]>, SignatureError> {
        match &self {
            MacKey::Hmac(key) => key.sign(message),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match &self {
            MacKey::Hmac(key) => key.algorithm(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::jws::Algorithm;
    use crate::crypto::symmetric::{MacKey, SymmetricKeyOperation};
    use aws_lc_rs::test::from_hex;

    #[test]
    fn test_hmac_sign() {
        let raw_key = "key";
        let raw_message = "The quick brown fox jumps over the lazy dog";
        let expected_signature =
            from_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();
        let key = MacKey::new_hmac(raw_key.as_bytes());

        let signature = key
            .sign(raw_message.as_bytes())
            .expect("HMAC signing failed");

        assert_eq!(
            signature.as_ref(),
            expected_signature.as_slice(),
            "Signature bytes not equal"
        );
    }

    #[test]
    fn test_hmac_algorithm() {
        let raw_key = "key";
        let expected_algorithm = Algorithm::HmacSha256;
        let key = MacKey::new_hmac(raw_key.as_bytes());

        let actual_algorithm = key.algorithm();

        assert_eq!(
            actual_algorithm, expected_algorithm,
            "Unexpected signature algorithm"
        );
    }
}
