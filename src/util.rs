pub(crate) mod serde_helper {
    use core::fmt;
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer};
    use std::ops::Deref;

    pub(crate) mod optional_offset_date_time {
        use serde::{self, Deserializer, Serializer};
        use std::option::Option;
        use time::serde::rfc3339;
        use time::OffsetDateTime;

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

    /// PassthroughBytes is a serde-deserializable type that simply takes in a byte array as input
    /// and deserializes it unchanged.
    #[derive(Debug)]
    pub struct PassthroughBytes {
        inner: Vec<u8>,
    }

    pub(crate) struct PassthroughBytesVisitor;

    impl<'de> Visitor<'de> for PassthroughBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte array")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(v)
        }
    }

    impl<'de> Deserialize<'de> for PassthroughBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = deserializer.deserialize_byte_buf(PassthroughBytesVisitor)?;
            Ok(Self { inner: bytes })
        }
    }

    impl Deref for PassthroughBytes {
        type Target = Vec<u8>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
}

#[cfg(test)]
mod tests {
    use super::serde_helper::optional_offset_date_time;
    use rstest::rstest;
    use time::macros::datetime;
    use time::OffsetDateTime;

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
}
