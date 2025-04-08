use hickory_resolver::Name;
use hickory_resolver::proto::rr::LowerName;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Eq)]
pub struct DnsName {
    inner: Name,
    ascii: String,
    utf8: String,
}

impl DnsName {
    fn __to_ascii(name: &Name) -> String {
        let ascii = name.to_ascii();
        ascii
            .strip_suffix(".")
            .map(ToString::to_string)
            .unwrap_or(ascii)
    }

    fn __to_utf8(name: &Name) -> String {
        let utf8 = name.to_utf8();
        utf8.strip_suffix(".")
            .map(ToString::to_string)
            .unwrap_or(utf8)
    }

    pub fn as_ascii(&self) -> &str {
        &self.ascii
    }

    pub fn as_utf8(&self) -> &str {
        &self.utf8
    }

    pub fn is_wildcard(&self) -> bool {
        self.inner.is_wildcard()
    }

    // TODO: Can probably be simplified
    pub fn eq_ignore_root(&self, other: &DnsName) -> bool {
        self.inner.eq_ignore_root(&other.inner)
    }

    pub fn to_acme_challenge_name(&self) -> Result<Self, ParseError> {
        let base = if self.is_wildcard() {
            &self.inner.base_name()
        } else {
            &self.inner
        };
        let acme_challenge_name = base.prepend_label("_acme-challenge")?;
        Ok(acme_challenge_name.into())
    }
}

impl PartialEq<Self> for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl PartialOrd for DnsName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }

    fn lt(&self, other: &Self) -> bool {
        self.inner.lt(&other.inner)
    }

    fn le(&self, other: &Self) -> bool {
        self.inner.le(&other.inner)
    }

    fn gt(&self, other: &Self) -> bool {
        self.inner.gt(&other.inner)
    }

    fn ge(&self, other: &Self) -> bool {
        self.inner.ge(&other.inner)
    }
}

impl Ord for DnsName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }

    fn max(self, other: Self) -> Self
    where
        Self: Sized,
    {
        DnsName::from(self.inner.max(other.inner))
    }

    fn min(self, other: Self) -> Self
    where
        Self: Sized,
    {
        DnsName::from(self.inner.min(other.inner))
    }

    fn clamp(self, min: Self, max: Self) -> Self
    where
        Self: Sized,
    {
        DnsName::from(self.inner.clamp(min.inner, max.inner))
    }
}

impl Hash for DnsName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl Display for DnsName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_utf8())
    }
}

impl From<&Name> for DnsName {
    fn from(value: &Name) -> Self {
        // Normalization: To avoid inconsistencies as much as possible:
        // - all names are lowercased. While this is not a RFC5280 requirement, it is commonly applied
        // - all names are treated as being absolute to the root (FQDN), as SANs do not distinguish between
        // relative and absolute domain names
        let mut normalized = value.to_lowercase();
        normalized.set_fqdn(true);
        let ascii = Self::__to_ascii(&normalized);
        let utf8 = Self::__to_utf8(&normalized);
        Self {
            inner: normalized,
            ascii,
            utf8,
        }
    }
}

impl From<Name> for DnsName {
    fn from(value: Name) -> Self {
        (&value).into()
    }
}

impl From<DnsName> for Name {
    fn from(value: DnsName) -> Self {
        value.inner
    }
}

impl From<&DnsName> for LowerName {
    fn from(value: &DnsName) -> Self {
        LowerName::new(&value.inner)
    }
}

impl From<DnsName> for LowerName {
    fn from(value: DnsName) -> Self {
        (&value).into()
    }
}

impl TryFrom<reqwest::dns::Name> for DnsName {
    type Error = ParseError;

    fn try_from(value: reqwest::dns::Name) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for DnsName {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Name::from_str_relaxed(value)?.into())
    }
}

impl TryFrom<String> for DnsName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl Serialize for DnsName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_utf8())
    }
}

struct DnsNameVisitor;

impl<'de> Visitor<'de> for DnsNameVisitor {
    type Value = DnsName;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a domain name string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        DnsName::try_from(v).map_err(|e| E::custom(e.to_string()))
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        DnsName::try_from(v).map_err(|e| E::custom(e.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        DnsName::try_from(v).map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for DnsName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DnsNameVisitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    ParseFailure(#[from] hickory_resolver::proto::ProtoError),
}

#[cfg(test)]
mod tests {
    use crate::dns::name::DnsName;
    use rstest::rstest;

    #[rstest]
    #[case("example.com", "example.com")]
    #[case("example.org", "example.org")]
    #[case("example.com.", "example.com")]
    #[case(".", "")]
    #[case("_underscore.name", "_underscore.name")]
    #[case("UPPERCASE.COM", "uppercase.com")]
    #[case("MiXeD.CaSe.", "mixed.case")]
    #[case("Bücher.example", "bücher.example")]
    #[case("Bücher.example.", "bücher.example")]
    #[case("xn--bcher-kva.example", "bücher.example")]
    #[case("allow_in_.EXAMPLE.com.", "allow_in_.example.com")]
    #[case("tld", "tld")]
    fn test_to_utf8(#[case] raw_name: &str, #[case] parsed_name: &str) {
        let parsed: DnsName = raw_name.try_into().unwrap();

        let display = parsed.as_utf8();

        assert_eq!(display, parsed_name);
    }

    #[rstest]
    #[case("example.com", "example.com")]
    #[case("example.org", "example.org")]
    #[case("example.com.", "example.com")]
    #[case(".", "")]
    #[case("_underscore.name", "_underscore.name")]
    #[case("UPPERCASE.COM", "uppercase.com")]
    #[case("MiXeD.CaSe.", "mixed.case")]
    #[case("Bücher.example", "xn--bcher-kva.example")]
    #[case("Bücher.example.", "xn--bcher-kva.example")]
    #[case("xn--bcher-kva.example", "xn--bcher-kva.example")]
    #[case("allow_in_.EXAMPLE.com.", "allow_in_.example.com")]
    #[case("tld", "tld")]
    fn test_to_ascii(#[case] raw_name: &str, #[case] ascii_name: &str) {
        let parsed: DnsName = raw_name.try_into().unwrap();

        let ascii_safe = parsed.as_ascii();

        assert_eq!(ascii_safe, ascii_name);
    }

    #[rstest]
    #[case("tld", false)]
    #[case("tld.", false)]
    #[case("a.tld", false)]
    #[case("a.tld.", false)]
    #[case("*.tld", true)]
    #[case("*.tld.", true)]
    #[case("_weird_name.*.example.com", false)]
    #[case("*.fqdn.example.com", true)]
    #[case("*", true)]
    fn test_is_wildcard(#[case] raw_name: &str, #[case] expected: bool) {
        let parsed: DnsName = raw_name.try_into().unwrap();

        let wildcard = parsed.is_wildcard();

        assert_eq!(wildcard, expected);
    }

    #[rstest]
    #[case("sub.example.com", "sub.example.com", true)]
    #[case("sub.example.com", "sub.example.com.", true)]
    #[case("sub.example.com.", "sub.example.com", true)]
    #[case("sub.example.com.", "sub.example.com.", true)]
    #[case("example.com", "sub.example.com", false)]
    #[case("example.com.", "sub.example.com", false)]
    #[case("example.com", "sub.example.com.", false)]
    #[case("example.com.", "sub.example.com.", false)]
    #[case("sub.example.com", "example.com", false)]
    #[case("sub.example.com", "example.com.", false)]
    #[case(".", ".", true)]
    #[case("tld", "tld.", true)]
    fn test_eq_ignore_root(
        #[case] first_name: &str,
        #[case] second_name: &str,
        #[case] expected: bool,
    ) {
        let first: DnsName = first_name.try_into().unwrap();
        let second: DnsName = second_name.try_into().unwrap();

        let equal = first.eq_ignore_root(&second);

        assert_eq!(equal, expected);
    }

    #[rstest]
    #[case("example.com", "_acme-challenge.example.com")]
    #[case("example.com.", "_acme-challenge.example.com.")]
    #[case("fqdn.example.com", "_acme-challenge.fqdn.example.com")]
    #[case(
        "_acme-challenge.example.com",
        "_acme-challenge._acme-challenge.example.com"
    )]
    #[case("*.example.com", "_acme-challenge.example.com.")]
    #[case("*.sub.example.com", "_acme-challenge.sub.example.com.")]
    fn test_to_acme_challenge_name(#[case] raw_name: &str, #[case] expected_name: &str) {
        let parsed: DnsName = raw_name.try_into().unwrap();
        let expected: DnsName = expected_name.try_into().unwrap();

        let equal = parsed.to_acme_challenge_name().unwrap();

        assert_eq!(equal, expected);
    }
}
