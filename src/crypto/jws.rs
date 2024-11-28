use crate::crypto::signing::{AsymmetricKeyOperation, Curve, KeyPair};
use crate::acme::object::Nonce;
use anyhow::Context;
use aws_lc_rs::digest::{digest, SHA256};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
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

#[derive(Debug, Serialize)]
pub enum Algorithm {
    #[serde(rename = "ES256")]
    EcdsaP256Sha256,
    #[serde(rename = "ES384")]
    EcdsaP384Sha384,
    #[serde(rename = "RS256")]
    RsaPkcs1Sha256,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum KeyParameters {
    #[serde(rename = "jwk")]
    NewAccount(JsonWebKeyParameters),
    #[serde(rename = "kid")]
    AccountUrl(Url),
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
        let hash = digest(&SHA256, fixed_serialization.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(hash.as_ref())
    }

    pub fn new(keypair: KeyPair) -> Self {
        let parameters = keypair.to_jwk_parameters();
        let thumbprint = JsonWebKey::compute_account_thumbprint(&parameters);
        Self {
            keypair,
            parameters: KeyParameters::NewAccount(parameters),
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
    ) -> anyhow::Result<FlatJsonWebSignature> {
        let header = serde_json::to_string(header).context("header serialization failed")?;
        let header = BASE64_URL_SAFE_NO_PAD.encode(header);
        let payload = match payload {
            None => "".to_string(),
            Some(payload) => {
                let payload =
                    serde_json::to_string(payload).context("payload serialization failed")?;
                BASE64_URL_SAFE_NO_PAD.encode(payload)
            }
        };
        let to_sign = format!("{}.{}", header, payload);
        let signature = self
            .keypair
            .sign(to_sign.as_bytes())
            .context("signing failed")?;
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlatJsonWebSignature {
    #[serde(rename = "protected")]
    header: String,
    payload: String,
    signature: String,
}

#[cfg(test)]
mod tests {
    use crate::crypto::jws::{
        Algorithm, JsonWebKey, JsonWebKeyEcdsa, JsonWebKeyParameters, JsonWebKeyRsa, KeyParameters,
        ProtectedHeader,
    };
    use crate::crypto::signing::Curve;
    use crate::acme::object::Nonce;
    use rstest::rstest;
    use url::Url;

    #[test]
    fn test_serialize_protected_header_with_ecdsa() {
        let header = ProtectedHeader {
            algorithm: Algorithm::EcdsaP256Sha256,
            nonce: Nonce::try_from("QWERTZ".to_string()).unwrap(),
            target_url: Url::parse("https://example.com/protected-header-test").unwrap(),
            key: KeyParameters::NewAccount(JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(
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
            key: KeyParameters::NewAccount(JsonWebKeyParameters::Rsa(JsonWebKeyRsa::new(
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
}
