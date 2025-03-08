use crate::crypto::jws::{Algorithm, JsonWebKeyEcdsa, JsonWebKeyParameters, JsonWebKeyRsa};
use anyhow::{Context, anyhow, bail};
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING};
use aws_lc_rs::{encoding, encoding::AsDer, rand::SystemRandom, rsa, signature};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use pem::Pem;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::OnceLock;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    Ecdsa(Curve),
    Rsa(rsa::KeySize),
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            KeyType::Ecdsa(curve) => write!(f, "ECDSA with {curve}"),
            KeyType::Rsa(size) => write!(f, "RSA-{}", size.len() * 8),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
}

impl Curve {
    pub fn get_jws_signing_algorithm(&self) -> &'static signature::EcdsaSigningAlgorithm {
        // Fixed signing means to return PKCS#11 signatures (raw r+s values, fixed size)
        // instead of ASN.1 signatures (DER encoded r+s). JOSE uses the former, so use them here too.
        match self {
            Curve::P256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
            Curve::P384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        }
    }
}

impl TryFrom<&str> for Curve {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "P-256" => Ok(Curve::P256),
            "P-384" => Ok(Curve::P384),
            _ => Err(anyhow!("Unknown EC curve {}", value)),
        }
    }
}

impl Display for Curve {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.as_str();
        write!(f, "{str}")
    }
}

#[derive(Debug)]
pub enum KeyPair {
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl KeyPair {
    pub fn save_to_disk(&self, file: File) -> anyhow::Result<()> {
        let pem = self.to_pem()?;
        save_key_to_file(&pem, file)
    }

    pub fn load_from_disk(file: File) -> anyhow::Result<Self> {
        let pem = load_file(file)?;
        KeyPair::from_pem(&pem)
    }

    pub fn get_jws_algorithm(&self) -> Algorithm {
        match self {
            KeyPair::Ecdsa(keypair) => match keypair.curve {
                Curve::P256 => Algorithm::EcdsaP256Sha256,
                Curve::P384 => Algorithm::EcdsaP384Sha384,
            },
            KeyPair::Rsa(_) => Algorithm::RsaPkcs1Sha256,
        }
    }

    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        // Parsing with rcgen + aws-lc-rs has the nice benefit that it supports various formats:
        // PKCS#1, PKCS#8, and SEC1. Thus, prefer it over parsing the pem ourselves.
        // (It also solves the problem of finding the correct algorithm and curve. rcgen
        // solves this by just deserializing all possible options and checks what works).
        let rcgen_keypair =
            rcgen::KeyPair::from_pem(pem).context("reading private key from pem failed")?;
        let pkcs8_der = rcgen_keypair.serialized_der();
        Ok(match rcgen_keypair.algorithm() {
            alg if alg == &rcgen::PKCS_ECDSA_P256_SHA256 => {
                KeyPair::Ecdsa(EcdsaKeyPair::from_pkcs8(Curve::P256, pkcs8_der)?)
            }
            alg if alg == &rcgen::PKCS_ECDSA_P384_SHA384 => {
                KeyPair::Ecdsa(EcdsaKeyPair::from_pkcs8(Curve::P384, pkcs8_der)?)
            }
            alg if alg == &rcgen::PKCS_RSA_SHA256
                || alg == &rcgen::PKCS_RSA_SHA384
                || alg == &rcgen::PKCS_RSA_SHA512 =>
            {
                KeyPair::Rsa(RsaKeyPair::from_pkcs8(pkcs8_der)?)
            }
            _ => bail!("unsupported algorithm in PEM"),
        })
    }

    pub fn to_rcgen_keypair(self) -> anyhow::Result<rcgen::KeyPair> {
        let pem = self.to_pem()?;
        Ok(rcgen::KeyPair::from_pem(&pem.to_string())?)
    }
}

impl EcdsaKeyPair {
    fn new(curve: Curve, keypair: signature::EcdsaKeyPair) -> Self {
        Self {
            curve,
            keypair,
            parameters: OnceLock::new(),
        }
    }
}

#[derive(Debug)]
pub struct EcdsaKeyPair {
    curve: Curve,
    keypair: signature::EcdsaKeyPair,
    parameters: OnceLock<JsonWebKeyParameters>,
}

#[derive(Debug)]
pub struct RsaKeyPair {
    keypair: signature::RsaKeyPair,
}

impl RsaKeyPair {
    fn new(keypair: signature::RsaKeyPair) -> Self {
        Self { keypair }
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait AsymmetricKeyOperation
where
    Self: Sized,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError>;
    fn to_pem(&self) -> Result<Pem, SignatureError>;
    fn to_jwk_parameters(&self) -> JsonWebKeyParameters;
}

impl AsymmetricKeyOperation for KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        match self {
            KeyPair::Ecdsa(keypair) => AsymmetricKeyOperation::sign(keypair, message),
            KeyPair::Rsa(keypair) => AsymmetricKeyOperation::sign(keypair, message),
        }
    }

    fn to_pem(&self) -> Result<Pem, SignatureError> {
        match self {
            KeyPair::Ecdsa(keypair) => AsymmetricKeyOperation::to_pem(keypair),
            KeyPair::Rsa(keypair) => AsymmetricKeyOperation::to_pem(keypair),
        }
    }

    fn to_jwk_parameters(&self) -> JsonWebKeyParameters {
        match self {
            KeyPair::Ecdsa(keypair) => AsymmetricKeyOperation::to_jwk_parameters(keypair),
            KeyPair::Rsa(keypair) => AsymmetricKeyOperation::to_jwk_parameters(keypair),
        }
    }
}

impl AsymmetricKeyOperation for EcdsaKeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let random = SystemRandom::new();
        let signature = self
            .keypair
            .sign(&random, message)
            .map_err(|_| SignatureError::SignatureGeneration("ECDSA signing failed"))?;
        let sig_bytes = signature.as_ref();
        Ok(sig_bytes.to_vec())
    }

    fn to_pem(&self) -> Result<Pem, SignatureError> {
        let data = self
            .keypair
            .to_pkcs8v1()
            .map_err(|_| SignatureError::EncodingFailed("Serializing ECDSA keypair failed"))?;
        let pem = Pem::new("PRIVATE KEY", data.as_ref());
        Ok(pem)
    }

    fn to_jwk_parameters(&self) -> JsonWebKeyParameters {
        self.parameters
            .get_or_init(|| {
                // For JOSE, we need the x and y points of our public curve point.
                // The most portable way to get them from our crypto library is to use X9.62 uncompressed curve
                // points, which are just the x and y bytes concatenated, except the first byte that
                // encodes some metadata.
                let pub_key = signature::KeyPair::public_key(&self.keypair);
                let pub_key_uncompressed_binary =
                    AsBigEndian::<encoding::EcPublicKeyUncompressedBin>::as_be_bytes(pub_key)
                        // The internet says all engines we care about support this (in fact, this is the
                        // default representation for many engines).
                        .expect(
                            "BUG: Crypto engine failed to provide public key in uncompressed form",
                        );
                let pub_key_bytes = pub_key_uncompressed_binary.as_ref();
                // Uncompressed public key - both coordinates present
                assert_eq!(pub_key_bytes[0], 0x04);
                let point_len = match self.curve {
                    Curve::P256 => 32,
                    Curve::P384 => 48,
                };
                let x = &pub_key_bytes[1..=point_len];
                let y = &pub_key_bytes[(1 + point_len)..];
                let x = BASE64_URL_SAFE_NO_PAD.encode(x);
                let y = BASE64_URL_SAFE_NO_PAD.encode(y);
                JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(self.curve, x, y))
            })
            .clone()
    }
}

impl EcdsaKeyPair {
    fn from_pkcs8(curve: Curve, der: &[u8]) -> anyhow::Result<Self> {
        let algorithm = curve.get_jws_signing_algorithm();
        let keypair = signature::EcdsaKeyPair::from_pkcs8(algorithm, der)
            .map_err(|_| anyhow!("ECDSA private key file is corrupted or invalid"))?;
        Ok(Self::new(curve, keypair))
    }
}

impl AsymmetricKeyOperation for RsaKeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let random = SystemRandom::new();
        let sig_len = self.keypair.public_modulus_len();
        let mut signature = vec![0; sig_len];
        self.keypair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &random,
                message,
                &mut signature,
            )
            .map_err(|_| SignatureError::SignatureGeneration("RSA signing failed"))?;
        Ok(signature)
    }

    fn to_pem(&self) -> Result<Pem, SignatureError> {
        let data = self
            .keypair
            .as_der()
            .map_err(|_| SignatureError::EncodingFailed("Serializing RSA keypair failed"))?;
        let pem = Pem::new("PRIVATE KEY", data.as_ref());
        Ok(pem)
    }

    fn to_jwk_parameters(&self) -> JsonWebKeyParameters {
        let public_key = signature::KeyPair::public_key(&self.keypair);
        let modulus = public_key.modulus();
        let exponent = public_key.exponent();
        let modulus = BASE64_URL_SAFE_NO_PAD.encode(modulus.big_endian_without_leading_zero());
        let exponent = BASE64_URL_SAFE_NO_PAD.encode(exponent.big_endian_without_leading_zero());
        JsonWebKeyParameters::Rsa(JsonWebKeyRsa::new(modulus, exponent))
    }
}

impl RsaKeyPair {
    pub fn from_pkcs8(der: &[u8]) -> anyhow::Result<Self> {
        let keypair = signature::RsaKeyPair::from_pkcs8(der)
            .map_err(|_| anyhow!("RSA private key file is corrupted or invalid"))?;
        Ok(Self::new(keypair))
    }
}

fn save_key_to_file(pem: &Pem, mut file: File) -> anyhow::Result<()> {
    file.write_all(pem.to_string().as_bytes())
        .context("writing private key to file failed")?;
    Ok(())
}

fn load_file(mut file: File) -> anyhow::Result<String> {
    let size_hint = file
        .metadata()
        .ok()
        .and_then(|m| usize::try_from(m.len()).ok())
        .unwrap_or(0);
    let mut contents = String::with_capacity(size_hint);
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

pub fn new_key(typ: KeyType) -> anyhow::Result<KeyPair> {
    Ok(match typ {
        KeyType::Ecdsa(curve) => {
            let algorithm = curve.get_jws_signing_algorithm();
            let keypair = signature::EcdsaKeyPair::generate(algorithm)
                .map_err(|_| anyhow!("Could not generate key"))?;
            KeyPair::Ecdsa(EcdsaKeyPair::new(curve, keypair))
        }
        KeyType::Rsa(size) => {
            let keypair = signature::RsaKeyPair::generate(size)
                .map_err(|_| anyhow!("Could not generate key"))?;
            KeyPair::Rsa(RsaKeyPair::new(keypair))
        }
    })
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

#[cfg(test)]
mod tests {
    use crate::crypto::asymmetric::{AsymmetricKeyOperation, Curve, KeyPair, KeyType, new_key};
    use crate::crypto::jws::{JsonWebKeyEcdsa, JsonWebKeyParameters, JsonWebKeyRsa};
    use aws_lc_rs::rsa::KeySize;
    use rstest::*;
    use std::fs::File;
    use std::io::{Seek, SeekFrom};

    const TEST_RSA_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCWJHc1oz671CoI
oxovl5pTtgPtl5bCc0KPGECc15Ob4bRp2pvp5hUTeJ7L/RP/sGkid4MUwvBckA9O
VYqO0FEAa4hwxp+ASQa3cKpIBDIAr7wc64MUwSmzBbF+DXK+oX/P7ukg4/Yr6oPk
XdR9PF3T4sQFBUJH0fgg9IiOj83amoH/djhjfyg35GEgcPXSJ5MNhbkpHSVijCXW
Za2dNm9XleN5RbzkUokOkBdzbXMxQesC+jCuh2lZUSq4cgJ2bE59lM+nM9p1HLuw
DeOxJZA2vpLCxQcMBp5LITBsbv2IRzfq8eqAP8ZS1SNad7ygRAfMErxLVQ83IJqb
+9pOq4rrAgMBAAECggEAA18rRcbtsyqcaulN+mg7zefsncrBVt/45fsqezs3vNUS
uxtMqal5qxfF7jsEkkHGT3Qkf43lCJC3x8+aTnqK0UbUrFg39PeqmaXQLJ2ngOHX
1TOhccykT6hnTpUlmV0Wgoyd3oa4lBuQxjoXehgdZD399DVxZE9PDiwBzkVCzi2Q
j5o33Wx3wjWuFhIOU5zkuMyswUkn1YpayAZvMuioEDiAGKE77WKE6EwUSDsb1hAc
U8hgukKtYmIj40D1VIsFzPwnimgikRrY5xzuUrRNQBPhG48ge5+gBmatYdl6p9Iu
eEyQ/DV1F5EEzK+e3kh62rXQmkcqxNoXpr278rJZlQKBgQDHPLstVyoDl9dzLOit
PzPVNx3q/FHhzbGnxAVWgLTZ88bll2GbB0mrgzoI+N1VjQnTE/lNI0lF1Ky9tF/7
9ySCHc1ujTWDBO6QBH3hE9DKVCsGQOwx2a1gJOFOa6FM7NxzGiytR7BPP942VwAa
P7YvrroZIPfoQPAG5M6FoLK2NQKBgQDA6wfPD3O4FxU7pEuJwsPQm2Bc4fl4gyR6
Kt1Lh+8Sic8uHGHRUGPHm4bMXjNb5lZfWVaZZGUoTXPU9UQPLTTBfWuZFRY6awAR
tqpp9sXcE+Ikwa1dEIQJCnEcZWliG5BzpAtFNwW3Mi9dJviMtBnZKPWQeVIfOsgA
24ESzwbgnwKBgQC0ZE5tTQBjZHXUeJLrWdBKeq8B9hcFRcJWzeqvWbVlqY0qj5f2
T/Dp89T2Dq4IKbz9epY8u3g6W8dTtB87+Zb6oJVCRWRwDmUZzJdU1SY0K2URMnMo
55hM9tdws47GIaewJ8DP25rNBlziAn+7RHhmT+N7oRgVF8a71ysOXmOxCQKBgQCf
CiNp5Ac2IHF0tcFAVLwxYaZTbEfJvfN4c5X0CqBg3BNcpDFP6cIYcHL0UERu4rkZ
6gCmfEmYrCFt0rTE/jObv9XQYb3tcwCfmcNrj/EVuZ6ZRsGxE0iGW4FcM45pPugb
LYXNDcs8d7bsSJBnDqKwkD/BVwMIk+EGM+94ngvBaQKBgQCFY3daymFVO8Pnt04H
O+ORvHJvW2Lh7SBnCZ89D0cvAxGp0SC1oKESYcojgYr/CpbxiIhxl1Bg3AcZKZtM
VQ01fXyGKXqVVyqeBtO61DQ3jeaaOxin2y+aVgK4VcQPSwTaROkGh9h/PJDkckje
gx3YYHRvwD/CSwcZ4Nky0m1cQA==
-----END PRIVATE KEY-----";

    const TEST_EC_256: &str = r"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmF8wlnVbLPlB8AEj
k4lKhdEK0BKxzqhrjYLmZFFauzKhRANCAARbKKWKAcWrBLHr5p9m1jjSjo0pokSi
Ts/gRi0PCIxJxZOwIKTPHvoECsgYRzZJxwz6B0Vk4QYkIeEFzjg2h/Wj
-----END PRIVATE KEY-----
";

    const TEST_EC_384: &str = r"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCox+o8d2IzZRUaW91Q
+5XhSTvppqz3IE6zp+t+eV7cjN+03FpjYdzI5MUoYMDvuw2hZANiAASpYDU237gY
F2L24KJSs/NlEHyXs6tKebsin6uVklyDu3WB7aS9NfKatnNF4Dm4l8fxtXU0bDMk
TJewtdXtUp5YK9kffYrWgDuhjq4X2SiUmOdYdDKzleh2ebpLokzCSxk=
-----END PRIVATE KEY-----
";

    fn temp_file() -> File {
        tempfile::tempfile().unwrap()
    }

    fn compare_ignore_newlines(expected: &str, actual: &str) {
        let expected_lines: Vec<_> = expected.lines().collect();
        let actual_lines: Vec<_> = actual.lines().collect();
        for (i, (expected, actual)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
            assert_eq!(
                expected, actual,
                "lines not equal, first difference at line {i}, expected {expected} got {actual}"
            );
        }
        let expected_len = expected_lines.len();
        let actual_len = actual_lines.len();
        assert_eq!(
            expected_len, actual_len,
            "expected and actual do not have the same number of lines, expected has {expected_len} while actual has {actual_len}"
        );
    }

    #[rstest]
    #[case::p256(KeyType::Ecdsa(Curve::P256))]
    #[case::p384(KeyType::Ecdsa(Curve::P384))]
    #[case::rsa2048(KeyType::Rsa(KeySize::Rsa2048))]
    #[case::rsa3072(KeyType::Rsa(KeySize::Rsa3072))]
    #[case::rsa4096(KeyType::Rsa(KeySize::Rsa4096))]
    fn test_new_key(#[case] key_type: KeyType) {
        let _ = new_key(key_type).expect("Key generation should not have failed");
    }

    #[test]
    fn test_new_key_with_ecdsa_p256() {
        let mut file = temp_file();
        let keypair =
            new_key(KeyType::Ecdsa(Curve::P256)).expect("Key generation should not have failed");
        keypair.save_to_disk(file.try_clone().unwrap()).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let _ = KeyPair::load_from_disk(file).unwrap();
    }

    #[rstest]
    #[case::p256(TEST_EC_256, JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(
            Curve::P256,
            "WyiligHFqwSx6-afZtY40o6NKaJEok7P4EYtDwiMScU".to_string(),
            "k7AgpM8e-gQKyBhHNknHDPoHRWThBiQh4QXOODaH9aM".to_string(),
    )))]
    #[case::p384(TEST_EC_384, JsonWebKeyParameters::Ecdsa(JsonWebKeyEcdsa::new(
            Curve::P384,
            "qWA1Nt-4GBdi9uCiUrPzZRB8l7OrSnm7Ip-rlZJcg7t1ge2kvTXymrZzReA5uJfH".to_string(),
            "8bV1NGwzJEyXsLXV7VKeWCvZH32K1oA7oY6uF9kolJjnWHQys5Xodnm6S6JMwksZ".to_string(),
    )))]
    #[case::rsa2048(TEST_RSA_PEM, JsonWebKeyParameters::Rsa(JsonWebKeyRsa::new(
                "liR3NaM-u9QqCKMaL5eaU7YD7ZeWwnNCjxhAnNeTm-G0adqb6eYVE3iey_0T_7BpIneDFMLwXJAPTlWKjtBRAGuIcMafgEkGt3CqSAQyAK-8HOuDFMEpswWxfg1yvqF_z-7pIOP2K-qD5F3UfTxd0-LEBQVCR9H4IPSIjo_N2pqB_3Y4Y38oN-RhIHD10ieTDYW5KR0lYowl1mWtnTZvV5XjeUW85FKJDpAXc21zMUHrAvowrodpWVEquHICdmxOfZTPpzPadRy7sA3jsSWQNr6SwsUHDAaeSyEwbG79iEc36vHqgD_GUtUjWne8oEQHzBK8S1UPNyCam_vaTquK6w".to_string(),
                "AQAB".to_string())))]
    fn test_to_jwk_parameters(
        #[case] test_pem: &'static str,
        #[case] expected_jwk: JsonWebKeyParameters,
    ) {
        let keypair = KeyPair::from_pem(test_pem).unwrap();
        let actual_jwk = keypair.to_jwk_parameters();
        assert_eq!(expected_jwk, actual_jwk, "JWK serialization not equal");
    }

    #[rstest]
    #[case::p256(TEST_EC_256)]
    #[case::p384(TEST_EC_384)]
    #[case::rsa2048(TEST_RSA_PEM)]
    fn test_to_pem(#[case] expected_pem: &'static str) {
        let keypair = KeyPair::from_pem(expected_pem).unwrap();
        let actual_pem = keypair.to_pem().expect("pem serialization failed");
        compare_ignore_newlines(expected_pem, &actual_pem.to_string());
    }

    #[rstest]
    #[case::p256(TEST_EC_256, 64)]
    #[case::p384(TEST_EC_384, 96)]
    #[case::rsa2048(TEST_RSA_PEM, 256)]
    fn test_sign_length(#[case] expected_pem: &'static str, #[case] expected_length: usize) {
        let message = "Hello, world!".as_bytes();
        let keypair = KeyPair::from_pem(expected_pem).unwrap();

        let signature = keypair.sign(message).expect("signing must not fail");
        assert_eq!(
            signature.len(),
            expected_length,
            "signature has invalid length"
        );
    }

    #[rstest]
    #[case::p256(TEST_EC_256)]
    #[case::p384(TEST_EC_384)]
    #[case::rsa2048(TEST_RSA_PEM)]
    fn test_save_and_load(#[case] test_pem: &'static str) {
        let mut file = temp_file();
        let keypair = KeyPair::from_pem(test_pem).unwrap();
        keypair.save_to_disk(file.try_clone().unwrap()).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let loaded_keypair = KeyPair::load_from_disk(file).unwrap();
        assert_eq!(
            keypair.to_jwk_parameters(),
            loaded_keypair.to_jwk_parameters(),
            "loaded key not equal to generated key"
        );
    }
}
