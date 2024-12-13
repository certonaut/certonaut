use anyhow::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use toml_edit::DocumentMut;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
pub struct TomlConfiguration {
    document: DocumentMut,
}

impl TomlConfiguration {
    fn load_toml<P: AsRef<Path>>(file: P) -> Result<Self, Error> {
        let document = std::fs::read_to_string(file)?;
        let document = toml_edit::DocumentMut::from_str(&document)?;
        Ok(Self { document })
    }

    fn write_toml<P: AsRef<Path>>(&mut self, file: P) -> Result<(), Error> {
        // This is a bit annoying, but apparently we cannot directly pretty-serialize
        let toml = &self.document.to_string();
        if let Some(parent) = file.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(file, toml)?;
        Ok(())
    }

    fn into_configuration<T>(self) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        Ok(toml_edit::de::from_document(self.document)?)
    }

    fn edit_toml<T>(&mut self, config: &T) -> Result<(), Error>
    where
        T: Serialize,
    {
        // TODO: Manually ensure that comments are kept by merging. For now, ignore.
        // Manually prettify by serializing and deserializing
        let pretty_string = toml_edit::ser::to_string_pretty(&config)?;
        let document = toml_edit::DocumentMut::from_str(&pretty_string)?;
        // This doesn't prettify
        //let document = toml_edit::ser::to_document(config)?;
        self.document = document;
        Ok(())
    }

    pub fn load<P: AsRef<Path>, T>(file: P) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        let toml = Self::load_toml(file)?;
        toml.into_configuration()
    }

    pub fn save<T, P: AsRef<Path>>(config: &T, file: P) -> Result<(), Error>
    where
        T: Serialize,
    {
        let mut toml = Self::load_toml(&file).unwrap_or(TomlConfiguration {
            document: DocumentMut::default(),
        });
        toml.edit_toml(config)?;
        toml.write_toml(file)
    }
}
