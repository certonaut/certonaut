use std::fmt::{Debug, Display};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Url {
    inner: url::Url,
}

impl Url {
    pub fn parse(input: &str) -> Result<Self, url::ParseError> {
        let url = url::Url::parse(input)?;
        Ok(Url { inner: url })
    }

    #[allow(clippy::result_unit_err)] // just mirroring what url::Url does
    pub fn from_file_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ()> {
        let url = url::Url::from_file_path(path)?;
        Ok(Url { inner: url })
    }

    pub fn join(&self, input: &str) -> Result<Self, url::ParseError> {
        let url = self.inner.join(input)?;
        Ok(Url { inner: url })
    }

    pub fn into_url(self) -> url::Url {
        self.inner
    }
}

impl Deref for Url {
    type Target = url::Url;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Url {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Url { inner: value }
    }
}

impl From<&url::Url> for Url {
    fn from(value: &url::Url) -> Self {
        Url {
            inner: value.clone(),
        }
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        value.inner
    }
}

impl FromStr for Url {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::from_str(s)?;
        Ok(Url { inner: url })
    }
}

impl Debug for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl serde::Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        url::Url::serialize(&self.inner, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let url = url::Url::deserialize(deserializer)?;
        Ok(Url { inner: url })
    }
}
