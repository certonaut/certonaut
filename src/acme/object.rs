use crate::acme::error::{Error, Problem};
use crate::crypto::jws::FlatJsonWebSignature;
use crate::util::serde_helper::optional_offset_date_time;
use anyhow::Context;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use time::serde::rfc3339;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Directory {
    pub new_nonce: Url,
    pub new_account: Url,
    pub new_order: Url,
    pub new_authz: Option<Url>,
    pub revoke_cert: Url,
    pub key_change: Url,
    pub renewal_info: Option<Url>,
    pub meta: Option<Metadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Metadata {
    pub terms_of_service: Option<Url>,
    pub website: Option<Url>,
    #[serde(default)]
    pub caa_identities: Vec<String>,
    #[serde(default)]
    pub external_account_required: bool,
    #[serde(default)]
    pub profiles: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Nonce(String);

impl Nonce {
    pub fn new_empty() -> Self {
        Self(String::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<String> for Nonce {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        for char in value.chars() {
            if char.is_ascii_alphanumeric() || char == '_' || char == '-' {
                continue;
            }
            return Err(Error::ProtocolViolation("Invalid nonce value"));
        }
        Ok(Self(value))
    }
}

impl FromStr for Nonce {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Nonce::try_from(s.to_string())
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Token(String);

impl TryFrom<String> for Token {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        for char in value.chars() {
            if char.is_ascii_alphanumeric() || char == '_' || char == '-' {
                continue;
            }
            return Err(Error::ProtocolViolation("Invalid token value"));
        }
        Ok(Self(value))
    }
}

impl FromStr for Token {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Token::try_from(s.to_string())
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Token {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRequest {
    #[serde(default)]
    pub contact: Vec<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<FlatJsonWebSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Account {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<Url>,
    pub orders: Option<Url>,
    #[serde(default)]
    pub external_account_binding: Option<FlatJsonWebSignature>,
    // TODO: Orders (not supported by Boulder)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
    #[serde(other)]
    Unknown,
}

impl Display for AccountStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AccountStatus::Valid => "valid",
                AccountStatus::Deactivated => "deactivated",
                AccountStatus::Revoked => "revoked",
                AccountStatus::Unknown => "unknown",
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum Identifier {
    Dns {
        value: String,
    },
    Ip {
        value: IpAddr,
    },
    #[serde(other)]
    Unknown,
}

impl From<String> for Identifier {
    fn from(value: String) -> Self {
        match value.parse::<IpAddr>() {
            Ok(ip) => Identifier::Ip { value: ip },
            Err(_) => Identifier::Dns { value },
        }
    }
}

impl From<IpAddr> for Identifier {
    fn from(value: IpAddr) -> Self {
        Identifier::Ip { value }
    }
}

impl FromStr for Identifier {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<IpAddr>() {
            Ok(ip) => Ok(Identifier::Ip { value: ip }),
            Err(_) => Ok(Identifier::Dns {
                value: s.to_string(),
            }),
        }
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.to_string()
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value: Cow<str> = match &self {
            Identifier::Dns { value } => value.as_str().into(),
            Identifier::Ip { value } => value.to_string().into(),
            Identifier::Unknown => "unknown".into(),
        };
        write!(f, "{value}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderRequest {
    pub identifiers: Vec<Identifier>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_offset_date_time"
    )]
    pub not_before: Option<time::OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_offset_date_time"
    )]
    pub not_after: Option<time::OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<AcmeRenewalIdentifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Order {
    pub status: OrderStatus,
    #[serde(default, with = "optional_offset_date_time")]
    pub expires: Option<time::OffsetDateTime>,
    pub identifiers: Vec<Identifier>,
    #[serde(default, with = "optional_offset_date_time")]
    pub not_before: Option<time::OffsetDateTime>,
    #[serde(default, with = "optional_offset_date_time")]
    pub not_after: Option<time::OffsetDateTime>,
    pub error: Option<Problem>,
    pub authorizations: Vec<Url>,
    pub finalize: Url,
    pub certificate: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<AcmeRenewalIdentifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    #[serde(other)]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    #[serde(default, with = "optional_offset_date_time")]
    pub expires: Option<time::OffsetDateTime>,
    pub challenges: Vec<Challenge>,
    #[serde(default)]
    pub wildcard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Deactivated,
    Expired,
    Revoked,
    #[serde(other)]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct Challenge {
    pub url: Url,
    pub status: ChallengeStatus,
    #[serde(default, with = "optional_offset_date_time")]
    pub validated: Option<time::OffsetDateTime>,
    pub error: Option<Problem>,
    #[serde(flatten)]
    pub inner_challenge: InnerChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    #[serde(other)]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
#[cfg_attr(test, derive(Serialize))]
pub enum InnerChallenge {
    #[serde(rename = "http-01")]
    Http(HttpChallenge),
    #[serde(rename = "dns-01")]
    Dns(DnsChallenge),
    #[serde(rename = "tls-alpn-01")]
    Alpn(AlpnChallenge),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct HttpChallenge {
    pub token: Token,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct DnsChallenge {
    pub token: Token,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct AlpnChallenge {
    pub token: Token,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct EmptyObject {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeRequest {
    pub csr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deactivation {
    pub status: &'static str,
}

impl Deactivation {
    pub fn new() -> Self {
        Self {
            status: "deactivated",
        }
    }
}

impl Default for Deactivation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revocation {
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
}

/// Reason codes as per RFC5280 section 5.3.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RevocationReason {
    #[default]
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AttributeAuthorityCompromise = 10,
}

impl Serialize for RevocationReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self as u8).serialize(serializer)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(Serialize, PartialEq, Eq))]
#[serde(rename_all = "camelCase")]
pub struct RenewalInfo {
    pub suggested_window: SuggestedWindow,
    // Annoying spec bug: Capitalising all URL letters is not camelCase, as is usually used in ACME
    #[serde(rename = "explanationURL")]
    pub explanation_url: Option<Url>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(Serialize, PartialEq, Eq))]
#[serde(rename_all = "camelCase")]
pub struct SuggestedWindow {
    #[serde(with = "rfc3339")]
    pub start: time::OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub end: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeRenewalIdentifier {
    key_identifier_base64: String,
    serial_base64: String,
}

impl AcmeRenewalIdentifier {
    pub fn new(key_identifier: &[u8], serial: &[u8]) -> Self {
        Self {
            key_identifier_base64: BASE64_URL_SAFE_NO_PAD.encode(key_identifier),
            serial_base64: BASE64_URL_SAFE_NO_PAD.encode(serial),
        }
    }

    pub(crate) fn try_from_string_raw(identifier: &str) -> anyhow::Result<Self> {
        let mut split = identifier.split('.');
        let aki = split
            .next()
            .context("AcmeRenewalIdentifier has invalid formatting")?;
        let serial = split
            .next()
            .context("AcmeRenewalIdentifier has invalid formatting")?;
        Ok(Self {
            key_identifier_base64: aki.to_string(),
            serial_base64: serial.to_string(),
        })
    }
}

impl Display for AcmeRenewalIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let aki = &self.key_identifier_base64;
        let serial = &self.serial_base64;
        write!(f, "{aki}.{serial}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::fs::File;
    use std::path::PathBuf;
    use std::string::ToString;
    use time::macros::datetime;

    #[rstest]
    fn test_deserialize_directory_valid(
        #[files("testdata/serialization/deserialize_test_directory_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Directory = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_directory_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_directory_*.json")]
        testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Directory> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_metadata_valid(
        #[files("testdata/serialization/deserialize_test_metadata_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Metadata = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_metadata_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_metadata_*.json")]
        testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Metadata> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_nonce_valid(
        #[files("testdata/serialization/deserialize_test_nonce_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Nonce = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_nonce_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_nonce_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Nonce> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_token_valid(
        #[files("testdata/serialization/deserialize_test_token_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Token = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_token_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_token_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Token> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_account_valid(
        #[files("testdata/serialization/deserialize_test_account_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Account = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_account_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_account_*.json")]
        testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Account> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_order_valid(
        #[files("testdata/serialization/deserialize_test_order_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Order = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_order_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_order_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Order> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_authorization_valid(
        #[files("testdata/serialization/deserialize_test_authz_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Authorization =
            serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_authorization_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_authz_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Authorization> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    fn test_deserialize_challenge_valid(
        #[files("testdata/serialization/deserialize_test_challenge_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: Challenge = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_challenge_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_challenge_*.json")]
        testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<Challenge> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    #[case("\"valid\"", AccountStatus::Valid)]
    #[case("\"deactivated\"", AccountStatus::Deactivated)]
    #[case("\"revoked\"", AccountStatus::Revoked)]
    #[case("\"newExtendedAccountStatus\"", AccountStatus::Unknown)]
    fn test_deserialize_account_status(#[case] test_value: &str, #[case] expected: AccountStatus) {
        let account_status: AccountStatus = serde_json::from_str(test_value).unwrap();
        assert_eq!(account_status, expected);
    }

    #[rstest]
    #[case(r#"{"type":"dns","value":"example.com"}"#, "example.com")]
    #[case(r#"{"type":"ip","value":"2001:db8::1"}"#, "2001:db8::1")]
    #[case(r#"{"type":"ip","value":"192.0.2.0"}"#, "192.0.2.0")]
    fn test_deserialize_identifier(#[case] test_value: &str, #[case] expected: Identifier) {
        let identifier: Identifier = serde_json::from_str(test_value).unwrap();
        assert_eq!(identifier, expected);
    }

    #[rstest]
    #[case("\"pending\"", OrderStatus::Pending)]
    #[case("\"ready\"", OrderStatus::Ready)]
    #[case("\"processing\"", OrderStatus::Processing)]
    #[case("\"valid\"", OrderStatus::Valid)]
    #[case("\"invalid\"", OrderStatus::Invalid)]
    #[case("\"garbageStatus\"", OrderStatus::Invalid)]
    fn test_deserialize_order_status(#[case] test_value: &str, #[case] expected: OrderStatus) {
        let order_status: OrderStatus = serde_json::from_str(test_value).unwrap();
        assert_eq!(order_status, expected);
    }

    #[rstest]
    #[case("\"pending\"", AuthorizationStatus::Pending)]
    #[case("\"valid\"", AuthorizationStatus::Valid)]
    #[case("\"deactivated\"", AuthorizationStatus::Deactivated)]
    #[case("\"expired\"", AuthorizationStatus::Expired)]
    #[case("\"revoked\"", AuthorizationStatus::Revoked)]
    #[case("\"garbageStatus\"", AuthorizationStatus::Invalid)]
    fn test_deserialize_authorization_status(
        #[case] test_value: &str,
        #[case] expected: AuthorizationStatus,
    ) {
        let authz_status: AuthorizationStatus = serde_json::from_str(test_value).unwrap();
        assert_eq!(authz_status, expected);
    }

    #[rstest]
    #[case("\"pending\"", ChallengeStatus::Pending)]
    #[case("\"processing\"", ChallengeStatus::Processing)]
    #[case("\"valid\"", ChallengeStatus::Valid)]
    #[case("\"invalid\"", ChallengeStatus::Invalid)]
    #[case("\"garbageStatus\"", ChallengeStatus::Invalid)]
    fn test_deserialize_challenge_status(
        #[case] test_value: &str,
        #[case] expected: ChallengeStatus,
    ) {
        let challenge_status: ChallengeStatus = serde_json::from_str(test_value).unwrap();
        assert_eq!(challenge_status, expected);
    }

    #[rstest]
    #[case(r#"{"type":"http-01","token":"QWERTZ"}"#, InnerChallenge::Http(
        HttpChallenge{ token: Token::from_str("QWERTZ").unwrap() }
    ))]
    #[case(r#"{"type":"dns-01","token":"QWERTZ"}"#, InnerChallenge::Dns(
        DnsChallenge{ token: Token::from_str("QWERTZ").unwrap() }
    ))]
    #[case(r#"{"type":"tls-alpn-01","token":"QWERTZ"}"#, InnerChallenge::Alpn(
        AlpnChallenge{ token: Token::from_str("QWERTZ").unwrap() }
    ))]
    fn test_deserialize_inner_challenge(
        #[case] test_value: &str,
        #[case] expected: InnerChallenge,
    ) {
        let challenge: InnerChallenge = serde_json::from_str(test_value).unwrap();
        assert_eq!(challenge, expected);
    }

    #[rstest]
    #[case("UcHwwlbcs1kUcHLLOe_Buw", "\"UcHwwlbcs1kUcHLLOe_Buw\"")]
    fn test_serialize_nonce(#[case] nonce: Nonce, #[case] expected: &str) {
        let serialized = serde_json::to_string(&nonce).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[rstest]
    #[case(AccountRequest{
            contact: vec!(Url::parse("mailto:admin@example.org").unwrap()),
            terms_of_service_agreed: Some(true),
            external_account_binding: None,
            only_return_existing: None,
        }, r#"{"contact":["mailto:admin@example.org"],"termsOfServiceAgreed":true}"#)]
    #[case(
        AccountRequest{
            contact: vec!(Url::parse("mailto:admin@example.org").unwrap()),
            terms_of_service_agreed: Some(true),
            external_account_binding: Some(FlatJsonWebSignature::new_test_values("header", "payload", "signature")),
            only_return_existing: None,
            }, r#"{"contact":["mailto:admin@example.org"],"termsOfServiceAgreed":true,"externalAccountBinding":{"protected":"header","payload":"payload","signature":"signature"}}"#
    )]
    #[case(AccountRequest{
            contact: vec!(),
            terms_of_service_agreed: None,
            external_account_binding: None,
            only_return_existing: None,
        }, r#"{"contact":[]}"#)]
    fn test_serialize_account_request(
        #[case] account_request: AccountRequest,
        #[case] expected: &str,
    ) {
        let serialized =
            serde_json::to_string(&account_request).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[rstest]
    #[case("example.com", r#"{"type":"dns","value":"example.com"}"#)]
    #[case("2001:db8::1", r#"{"type":"ip","value":"2001:db8::1"}"#)]
    #[case("192.0.2.0", r#"{"type":"ip","value":"192.0.2.0"}"#)]
    fn test_serialize_identifier(#[case] identifier: Identifier, #[case] expected: &str) {
        let serialized = serde_json::to_string(&identifier).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[rstest]
    #[case(NewOrderRequest{
        identifiers: vec![Identifier::from_str("example.com").unwrap()],
        not_before: None,
        not_after: None,
        replaces: None,
        profile: None,
        },
        r#"{"identifiers":[{"type":"dns","value":"example.com"}]}"#)]
    #[case(NewOrderRequest{
        identifiers: vec![Identifier::from_str("example.com").unwrap(), Identifier::from_str("api.example.com").unwrap()],
        not_before: None,
        not_after: None,
        replaces: None,
        profile: None,
        },
        r#"{"identifiers":[{"type":"dns","value":"example.com"},{"type":"dns","value":"api.example.com"}]}"#)]
    #[case(NewOrderRequest{
        identifiers: vec![Identifier::from_str("example.com").unwrap()],
        not_before: Some(datetime!(2024-12-12 12:12:12 UTC)),
        not_after: Some(datetime!(2024-12-13 12:12:12 UTC)),
        replaces: None,
        profile: None,
        },
        r#"{"identifiers":[{"type":"dns","value":"example.com"}],"notBefore":"2024-12-12T12:12:12Z","notAfter":"2024-12-13T12:12:12Z"}"#
    )]
    #[case(NewOrderRequest{
        identifiers: vec![Identifier::from_str("example.com").unwrap()],
        not_before: Some(datetime!(2024-12-12 12:12:12 UTC)),
        not_after: Some(datetime!(2024-12-13 12:12:12 UTC)),
        replaces: Some(AcmeRenewalIdentifier::new(&[0xDE,0xAD], &[0xBE, 0xEF])),
        profile: None,
        },
        r#"{"identifiers":[{"type":"dns","value":"example.com"}],"notBefore":"2024-12-12T12:12:12Z","notAfter":"2024-12-13T12:12:12Z","replaces":"3q0.vu8"}"#
    )]
    #[case(NewOrderRequest{
        identifiers: vec![Identifier::from_str("example.com").unwrap()],
        not_before: Some(datetime!(2024-12-12 12:12:12 UTC)),
        not_after: Some(datetime!(2024-12-13 12:12:12 UTC)),
        replaces: Some(AcmeRenewalIdentifier::new(&[0xDE,0xAD], &[0xBE, 0xEF])),
        profile: Some("some-profile".to_string()),
        },
        r#"{"identifiers":[{"type":"dns","value":"example.com"}],"notBefore":"2024-12-12T12:12:12Z","notAfter":"2024-12-13T12:12:12Z","replaces":"3q0.vu8","profile":"some-profile"}"#
    )]
    fn test_serialize_new_order_request(#[case] request: NewOrderRequest, #[case] expected: &str) {
        let serialized = serde_json::to_string(&request).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_empty_object() {
        let empty = EmptyObject {};
        let serialized = serde_json::to_string(&empty).expect("serialization must not fail");
        assert_eq!(serialized, r"{}");
    }

    #[rstest]
    #[case(FinalizeRequest{
            csr: "CSRPlaceholder".to_string(),
        }, r#"{"csr":"CSRPlaceholder"}"#)]
    fn test_serialize_finalize_request(
        #[case] finalize_request: FinalizeRequest,
        #[case] expected: &str,
    ) {
        let serialized =
            serde_json::to_string(&finalize_request).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[rstest]
    #[case("someToken", r#""someToken""#)]
    fn test_serialize_token(#[case] token: Token, #[case] expected: &str) {
        let serialized = serde_json::to_string(&token).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_deactivated() {
        let serialized =
            serde_json::to_string(&Deactivation::new()).expect("serialization must not fail");
        assert_eq!(serialized, r#"{"status":"deactivated"}"#);
    }

    #[rstest]
    fn test_deserialize_renewal_info_valid(
        #[files("testdata/serialization/deserialize_test_renewalInfo_*.json")] testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let _: RenewalInfo = serde_json::from_reader(file).expect("Deserialization must not fail");
    }

    #[rstest]
    fn test_deserialize_renewal_info_invalid(
        #[files("testdata/serialization/deserialize_invalid_test_renewalInfo_*.json")]
        testfile: PathBuf,
    ) {
        let file = File::open(testfile).unwrap();
        let maybe_err: serde_json::Result<RenewalInfo> = serde_json::from_reader(file);
        maybe_err.expect_err("Deserialization must fail");
    }

    #[rstest]
    #[case(
        Revocation{certificate: "Base64PlaceHolder".to_string(), reason: None,}, r#"{"certificate":"Base64PlaceHolder"}"#
    )]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::Unspecified),},
        r#"{"certificate":"Base64PlaceHolder","reason":0}"#)]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::KeyCompromise),},
        r#"{"certificate":"Base64PlaceHolder","reason":1}"#)]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::CaCompromise),},
        r#"{"certificate":"Base64PlaceHolder","reason":2}"#)]
    #[case(
        Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::AffiliationChanged),},
        r#"{"certificate":"Base64PlaceHolder","reason":3}"#
    )]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::Superseded),},
        r#"{"certificate":"Base64PlaceHolder","reason":4}"#)]
    #[case(
        Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::CessationOfOperation),},
        r#"{"certificate":"Base64PlaceHolder","reason":5}"#
    )]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::CertificateHold),},
        r#"{"certificate":"Base64PlaceHolder","reason":6}"#)]
    #[case(Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::RemoveFromCrl),},
        r#"{"certificate":"Base64PlaceHolder","reason":8}"#)]
    #[case(
        Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::PrivilegeWithdrawn),},
        r#"{"certificate":"Base64PlaceHolder","reason":9}"#
    )]
    #[case(
        Revocation{certificate: "Base64PlaceHolder".to_string(), reason: Some(RevocationReason::AttributeAuthorityCompromise),},
        r#"{"certificate":"Base64PlaceHolder","reason":10}"#
    )]
    fn test_serialize_revocation(#[case] revocation: Revocation, #[case] expected: &str) {
        let serialized = serde_json::to_string(&revocation).expect("serialization must not fail");
        assert_eq!(serialized, expected);
    }

    // TODO: Add RFC tests where provided
    // TODO: Tests for logic outside of serde
}
