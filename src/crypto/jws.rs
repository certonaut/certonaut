use crate::acme::object::Nonce;
use crate::crypto::asymmetric::{AsymmetricKeyOperation, Curve, KeyPair};
use crate::crypto::symmetric::{MacKey, SymmetricKeyOperation};
use crate::crypto::{SignatureError, sha256};
use anyhow::Context;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize)]
pub struct ProtectedHeader {
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    #[serde(skip_serializing_if = "Nonce::is_empty")]
    pub nonce: Nonce,
    #[serde(rename = "url")]
    target_url: Url,
    #[serde(flatten)]
    key: KeyParameters,
}

impl ProtectedHeader {
    pub fn new(algorithm: Algorithm, nonce: Nonce, target_url: Url, key: KeyParameters) -> Self {
        Self {
            algorithm,
            nonce,
            target_url,
            key,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum Algorithm {
    #[serde(rename = "ES256")]
    EcdsaP256Sha256,
    #[serde(rename = "ES384")]
    EcdsaP384Sha384,
    #[serde(rename = "RS256")]
    RsaPkcs1Sha256,
    #[serde(rename = "HS256")]
    HmacSha256,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum KeyParameters {
    #[serde(rename = "jwk")]
    FullKey(JsonWebKeyParameters),
    #[serde(rename = "kid")]
    AccountUrl(Url),
    #[serde(rename = "kid")]
    ExternalKey(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum JsonWebKeyParameters {
    Ecdsa(JsonWebKeyEcdsa),
    Rsa(JsonWebKeyRsa),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonWebKeyEcdsa {
    #[serde(rename = "kty")]
    key_type: &'static str,
    #[serde(rename = "crv")]
    curve: Curve,
    #[serde(rename = "x")]
    x_coordinate: String,
    #[serde(rename = "y")]
    y_coordinate: String,
}

impl JsonWebKeyEcdsa {
    pub fn new(curve: Curve, x_coordinate: String, y_coordinate: String) -> Self {
        Self {
            key_type: "EC",
            curve,
            x_coordinate,
            y_coordinate,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonWebKeyRsa {
    #[serde(rename = "kty")]
    key_type: &'static str,
    #[serde(rename = "n")]
    modulus: String,
    #[serde(rename = "e")]
    exponent: String,
}

impl JsonWebKeyRsa {
    pub fn new(modulus: String, exponent: String) -> Self {
        Self {
            key_type: "RSA",
            modulus,
            exponent,
        }
    }
}

pub const EMPTY_PAYLOAD: Option<&()> = None;

#[derive(Debug)]
pub struct JsonWebKey {
    keypair: KeyPair,
    parameters: KeyParameters,
    thumbprint: String,
}

impl JsonWebKey {
    fn compute_account_thumbprint(parameters: &JsonWebKeyParameters) -> String {
        // serde_json can produce no-whitespace-no-linebreak JSON, but serde_json doesn't guarantee
        // any particular order (by default). The thumbprint relies on exact ordering however,
        // so we do the serialization manually here.
        let fixed_serialization = match parameters {
            JsonWebKeyParameters::Ecdsa(ecdsa) => {
                let crv = ecdsa.curve.as_str();
                let kty = ecdsa.key_type;
                let x = &ecdsa.x_coordinate;
                let y = &ecdsa.y_coordinate;
                format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#)
            }
            JsonWebKeyParameters::Rsa(rsa) => {
                let e = &rsa.exponent;
                let kty = rsa.key_type;
                let n = &rsa.modulus;
                format!(r#"{{"e":"{e}","kty":"{kty}","n":"{n}"}}"#)
            }
        };
        let hash = sha256(fixed_serialization.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_ref())
    }

    pub fn new(keypair: KeyPair) -> Self {
        let parameters = keypair.to_jwk_parameters();
        let thumbprint = JsonWebKey::compute_account_thumbprint(&parameters);
        Self {
            keypair,
            parameters: KeyParameters::FullKey(parameters),
            thumbprint,
        }
    }

    pub fn new_existing(keypair: KeyPair, url: Url) -> Self {
        let parameters = keypair.to_jwk_parameters();
        let thumbprint = JsonWebKey::compute_account_thumbprint(&parameters);
        Self {
            keypair,
            parameters: KeyParameters::AccountUrl(url),
            thumbprint,
        }
    }

    #[must_use]
    pub fn into_existing(self, account_url: Url) -> Self {
        Self::new_existing(self.keypair, account_url)
    }

    pub fn get_algorithm(&self) -> Algorithm {
        self.keypair.get_jws_algorithm()
    }

    pub fn get_parameters(&self) -> &KeyParameters {
        &self.parameters
    }

    pub fn sign<T: Serialize>(
        &self,
        header: &ProtectedHeader,
        payload: Option<&T>,
    ) -> Result<FlatJsonWebSignature, SignatureError> {
        let header = serde_json::to_string(header)?;
        let header = BASE64_URL_SAFE_NO_PAD.encode(header);
        let payload = match payload {
            None => String::new(),
            Some(payload) => {
                let payload = serde_json::to_string(payload)?;
                BASE64_URL_SAFE_NO_PAD.encode(payload)
            }
        };
        let to_sign = format!("{header}.{payload}");
        let signature = self.keypair.sign(to_sign.as_bytes())?;
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signature);
        Ok(FlatJsonWebSignature {
            header,
            payload,
            signature,
        })
    }

    pub fn get_acme_thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlatJsonWebSignature {
    #[serde(rename = "protected")]
    header: String,
    payload: String,
    signature: String,
}

#[cfg(test)]
impl FlatJsonWebSignature {
    pub fn new_test_values(header: &str, payload: &str, signature: &str) -> Self {
        Self {
            header: header.to_string(),
            payload: payload.to_string(),
            signature: signature.to_string(),
        }
    }
}

impl FlatJsonWebSignature {
    fn parse_base64_json(value: &str) -> anyhow::Result<serde_json::Value> {
        let raw_json = BASE64_URL_SAFE_NO_PAD.decode(value)?;
        Ok(serde_json::from_slice(&raw_json)?)
    }

    pub fn header_json(&self) -> anyhow::Result<serde_json::Value> {
        Self::parse_base64_json(&self.header)
    }

    pub fn payload_json(&self) -> anyhow::Result<serde_json::Value> {
        Self::parse_base64_json(&self.payload)
    }
}

#[derive(Debug)]
pub struct ExternalAccountBinding {
    key_id: String,
    key: MacKey,
}

impl ExternalAccountBinding {
    pub fn try_new(key_id: String, encoded_key: String) -> anyhow::Result<Self> {
        let key_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_key)
            .context("EAB key does not appear to be base64-url encoded. Check the key was entered correctly.")?;
        Ok(Self {
            key_id,
            key: MacKey::new_hmac(&key_bytes),
        })
    }

    pub fn sign(
        &self,
        url: Url,
        account_key: &JsonWebKey,
    ) -> Result<FlatJsonWebSignature, SignatureError> {
        let algorithm = self.key.algorithm();
        let header = ProtectedHeader {
            algorithm,
            nonce: Nonce::new_empty(),
            target_url: url,
            key: KeyParameters::ExternalKey(self.key_id.clone()),
        };
        let header = serde_json::to_string(&header)?;
        let header = BASE64_URL_SAFE_NO_PAD.encode(header);
        let payload = account_key.get_parameters();
        let KeyParameters::FullKey(payload) = payload else {
            return Err(SignatureError::EncodingFailed(
                "EAB signing requires a full account key",
            ));
        };
        let payload = serde_json::to_string(payload)?;
        let payload = BASE64_URL_SAFE_NO_PAD.encode(payload);
        let to_sign = format!("{header}.{payload}");
        let signature = self.key.sign(to_sign.as_bytes())?;
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signature);
        Ok(FlatJsonWebSignature {
            header,
            payload,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::acme::object::Nonce;
    use crate::crypto::asymmetric::{Curve, KeyPair};
    use crate::crypto::jws::{
        Algorithm, ExternalAccountBinding, JsonWebKey, JsonWebKeyEcdsa, JsonWebKeyParameters,
        JsonWebKeyRsa, KeyParameters, ProtectedHeader,
    };
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use rstest::rstest;
    use std::fs::File;
    use url::Url;

    #[test]
    fn test_serialize_protected_header_with_ecdsa() {
        let header = ProtectedHeader {
            algorithm: Algorithm::EcdsaP256Sha256,
            nonce: Nonce::try_from("QWERTZ".to_string()).unwrap(),
            target_url: Url::parse("https://example.com/protected-header-test").unwrap(),
            key: KeyParameters::FullKey(JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(
                Curve::P256,
                "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_string(),
                "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".to_string(),
            ))),
        };
        let expected_header = r#"{
  "alg": "ES256",
  "nonce": "QWERTZ",
  "url": "https://example.com/protected-header-test",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
  }
}"#;
        let actual_header = serde_json::to_string_pretty(&header).unwrap();
        assert_eq!(
            expected_header, actual_header,
            "serialization failed, expected {expected_header}, got {actual_header}"
        );
    }

    #[test]
    fn test_serialize_protected_header_with_rsa() {
        let header = ProtectedHeader {
            algorithm: Algorithm::RsaPkcs1Sha256,
            nonce: Nonce::try_from("QWERTZ".to_string()).unwrap(),
            target_url: Url::parse("https://example.com/protected-header-test").unwrap(),
            key: KeyParameters::FullKey(JsonWebKeyParameters::Rsa(JsonWebKeyRsa::new(
                "longModulusIsTooLongForTestSoThisSubstitutesBase64".to_string(),
                "AQAB".to_string(),
            ))),
        };
        let expected_header = r#"{
  "alg": "RS256",
  "nonce": "QWERTZ",
  "url": "https://example.com/protected-header-test",
  "jwk": {
    "kty": "RSA",
    "n": "longModulusIsTooLongForTestSoThisSubstitutesBase64",
    "e": "AQAB"
  }
}"#;
        let actual_header = serde_json::to_string_pretty(&header).unwrap();
        assert_eq!(
            expected_header, actual_header,
            "serialization failed, expected {expected_header}, got {actual_header}"
        );
    }

    #[rstest]
    #[case::rsa(JsonWebKeyParameters::Rsa(JsonWebKeyRsa::new("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string(), "AQAB".to_string())), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")]
    #[case::ecdsa(
        JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(
            Curve::P256,
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_string(),
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".to_string()
        )),
        "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
    )]
    fn test_compute_account_thumbprint(
        #[case] parameters: JsonWebKeyParameters,
        #[case] expected_thumbprint: &str,
    ) {
        let actual_thumbprint = JsonWebKey::compute_account_thumbprint(&parameters);
        assert_eq!(
            &actual_thumbprint, expected_thumbprint,
            "computed thumbprint not equal"
        );
    }

    #[test]
    fn test_external_account_binding_sign() -> anyhow::Result<()> {
        let eab = ExternalAccountBinding::try_new(
            "my-key-id".to_string(),
            BASE64_URL_SAFE_NO_PAD.encode("my-key"),
        )?;
        let test_url = Url::parse("https://example.com/eab-test")?;
        let test_key_file = File::open("testdata/keys/account.key")?;
        let test_key = JsonWebKey::new(KeyPair::load_from_disk(test_key_file)?);
        let expected_signature = r#"{
  "protected": "eyJhbGciOiJIUzI1NiIsInVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZWFiLXRlc3QiLCJraWQiOiJteS1rZXktaWQifQ",
  "payload": "eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6Ii1mZmVsbFhIb29qaEdzSG1YX2FDNnhQeHMwQ19pU2MyNFViT1dtZzY2Q2pZdnQ5YTJaLXFMSUZ2aGZmeUhPUlciLCJ5IjoiajVFX1luRFRHeHVsYjdXaEdXOXo4YjY2Tjk2dFFZd3F4VU10RmFMTW5Ld2JHSVZyMnVDVDdtZmFqRnItSTdwdCJ9",
  "signature": "AtwFS3r6nTz1nvAA7DNIrVlSoDFWMBPgUuCmiR0FJ2w"
}"#;

        let signature = eab.sign(test_url.clone(), &test_key)?;
        let signature_json = serde_json::to_string_pretty(&signature)?;

        assert_eq!(signature_json, expected_signature, "{signature_json}");
        Ok(())
    }
}
