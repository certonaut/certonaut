use itertools::Itertools;
use time::OffsetDateTime;

pub(crate) mod serde_helper {
    use core::fmt;
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer};
    use std::ops::Deref;
    use tokio_util::bytes::Bytes;

    pub(crate) mod optional_offset_date_time {
        use serde::{self, Deserializer, Serializer};
        use std::option::Option;
        use time::OffsetDateTime;
        use time::serde::rfc3339;

        #[allow(clippy::ref_option)]
        pub fn serialize<S>(
            input: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match input {
                None => serializer.serialize_none(),
                Some(time) => rfc3339::serialize(time, serializer),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
        where
            D: Deserializer<'de>,
        {
            rfc3339::deserialize(deserializer).map(Some)
        }
    }

    /// `PassthroughBytes` is a serde-deserializable type that simply takes in a byte array as input
    /// and deserializes it unchanged.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PassthroughBytes {
        inner: Bytes,
    }

    impl PassthroughBytes {
        #[cfg(test)]
        pub(crate) fn new(data: Bytes) -> Self {
            Self { inner: data }
        }
    }

    impl AsRef<[u8]> for PassthroughBytes {
        fn as_ref(&self) -> &[u8] {
            self.inner.as_ref()
        }
    }

    pub(crate) struct PassthroughBytesVisitor;

    impl Visitor<'_> for PassthroughBytesVisitor {
        type Value = Bytes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte array")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(Bytes::copy_from_slice(v))
        }

        fn visit_borrowed_bytes<E>(self, v: &'_ [u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(Bytes::copy_from_slice(v))
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(Bytes::from(v))
        }
    }

    impl<'de> Deserialize<'de> for PassthroughBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Bytes = deserializer.deserialize_byte_buf(PassthroughBytesVisitor)?;
            Ok(Self { inner: bytes })
        }
    }

    impl Deref for PassthroughBytes {
        type Target = Bytes;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    pub(crate) mod key_type_config_serializer {
        use crate::crypto::asymmetric::{Curve, KeyType};
        use aws_lc_rs::rsa::KeySize;
        use core::fmt;
        use serde::de::Visitor;
        use serde::ser::Error;
        use serde::{self, Deserializer, Serializer};
        use std::marker::PhantomData;

        #[allow(clippy::ref_option)]
        #[allow(clippy::trivially_copy_pass_by_ref)]
        pub fn serialize<S>(input: &KeyType, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match input {
                KeyType::Ecdsa(curve) => {
                    let name = "ECDSA-".to_string() + curve.as_str();
                    serializer.serialize_str(&name)
                }
                KeyType::Rsa(size) => {
                    let name = "RSA-".to_string()
                        + match size {
                            KeySize::Rsa2048 => "2048",
                            KeySize::Rsa3072 => "3072",
                            KeySize::Rsa4096 => "4096",
                            KeySize::Rsa8192 => "8192",
                            _ => return Err(Error::custom("unsupported key size")),
                        };
                    serializer.serialize_str(&name)
                }
            }
        }

        pub(crate) struct KeyTypeVisitor<E> {
            _marker: PhantomData<E>,
        }

        impl<E: serde::de::Error> KeyTypeVisitor<E> {
            fn deserialize(input: &str) -> Result<KeyType, E> {
                if let Some(curve) = input.strip_prefix("ECDSA-") {
                    let curve = Curve::try_from(curve).map_err(E::custom)?;
                    Ok(KeyType::Ecdsa(curve))
                } else if let Some(size) = input.strip_prefix("RSA-") {
                    let key_size = match size {
                        "2048" => KeySize::Rsa2048,
                        "3072" => KeySize::Rsa3072,
                        "4096" => KeySize::Rsa4096,
                        "8192" => KeySize::Rsa8192,
                        _ => return Err(E::custom(format!("unsupported key size {size}"))),
                    };
                    Ok(KeyType::Rsa(key_size))
                } else {
                    Err(E::unknown_variant(input, &["ECDSA-", "RSA-"]))
                }
            }
        }

        impl<'de, E1> Visitor<'de> for KeyTypeVisitor<E1> {
            type Value = KeyType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a key type string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KeyTypeVisitor::deserialize(v)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KeyTypeVisitor::deserialize(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KeyTypeVisitor::deserialize(&v)
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyType, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(KeyTypeVisitor::<D::Error> {
                _marker: PhantomData,
            })
        }
    }

    pub(crate) mod renewal_identifier_serializer {
        use crate::acme::object::AcmeRenewalIdentifier;
        use serde::de::{Error, Visitor};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::fmt::Formatter;

        impl Serialize for AcmeRenewalIdentifier {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        pub(crate) struct AcmeRenewalIdentifierVisitor;

        impl<'de> Visitor<'de> for AcmeRenewalIdentifierVisitor {
            type Value = AcmeRenewalIdentifier;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AcmeRenewalIdentifier::try_from_string_raw(v).map_err(|e| Error::custom(e))
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AcmeRenewalIdentifier::try_from_string_raw(v).map_err(|e| Error::custom(e))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AcmeRenewalIdentifier::try_from_string_raw(&v).map_err(|e| Error::custom(e))
            }
        }

        impl<'de> Deserialize<'de> for AcmeRenewalIdentifier {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_str(AcmeRenewalIdentifierVisitor)
            }
        }
    }
}

pub fn format_hex_with_colon<T: AsRef<[u8]>>(bytes: T) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).join(":")
}

#[allow(clippy::missing_panics_doc)]
pub fn truncate_to_millis(dt: OffsetDateTime) -> OffsetDateTime {
    let nanos = dt.nanosecond();
    let nanos_truncated = nanos - (nanos % 1_000_000); // truncate to millis
    dt.replace_nanosecond(nanos_truncated).unwrap(/* Infallible */)
}

#[cfg(test)]
mod tests {
    use super::serde_helper::optional_offset_date_time;
    use crate::util::format_hex_with_colon;
    use rstest::rstest;
    use time::OffsetDateTime;
    use time::macros::datetime;

    #[rstest]
    #[case("\"1985-04-12T23:20:50.52Z\"", Some(datetime!(1985-04-12 23:20:50.52 UTC)))]
    #[case("\"1996-12-19T16:39:57-08:00\"", Some(datetime!(1996-12-20 00:39:57 UTC)))]
    fn test_deserialize_optional_rfc339(
        #[case] test_value: &str,
        #[case] expected: Option<OffsetDateTime>,
    ) {
        let mut deserializer = serde_json::Deserializer::from_str(test_value);
        let date_time: Option<OffsetDateTime> =
            optional_offset_date_time::deserialize(&mut deserializer).unwrap();
        assert_eq!(date_time, expected);
    }

    #[rstest]
    #[case(Some(datetime!(1985-04-12 23:20:50.52 UTC)), "\"1985-04-12T23:20:50.52Z\"")]
    #[case(Some(datetime!(1996-12-20 00:39:57 UTC)), "\"1996-12-20T00:39:57Z\"")]
    #[case(None, "null")]
    fn test_serialize_optional_rfc339(
        #[case] test_value: Option<OffsetDateTime>,
        #[case] expected: &str,
    ) {
        let mut serialized = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut serialized);
        optional_offset_date_time::serialize(&test_value, &mut serializer).unwrap();
        assert_eq!(String::from_utf8_lossy(&serialized), expected);
    }

    #[rstest]
    #[case(&[], "")]
    #[case(&[0x00], "00")]
    #[case(&[0x12, 0x34], "12:34")]
    #[case(&[0xab, 0xcd, 0xef], "ab:cd:ef")]
    #[case(&[0xff, 0xaa, 0xbb], "ff:aa:bb")]
    fn test_format_hex_with_colon(#[case] input: &[u8], #[case] expected: &str) {
        assert_eq!(format_hex_with_colon(input), expected);
    }
}
