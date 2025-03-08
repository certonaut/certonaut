use anyhow::{Context, Error};
use serde::Serialize;
use serde::de::DeserializeOwned;
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
        let file = file.as_ref();
        let document = std::fs::read_to_string(file)
            .context(format!("Reading configuration file {}", file.display()))?;
        let document = toml_edit::DocumentMut::from_str(&document)
            .context(format!("Parsing configuration file {}", file.display()))?;
        Ok(Self { document })
    }

    fn write_toml<P: AsRef<Path>>(&mut self, file: P) -> Result<(), Error> {
        let file = file.as_ref();
        // This is a bit annoying, but apparently we cannot directly pretty-serialize
        let toml = &self.document.to_string();
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)
                .context(format!("Creating directory {}", parent.display()))?;
        }
        std::fs::write(file, toml)
            .context(format!("Saving configuration file {}", file.display()))?;
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
        let filename = file.as_ref();
        let toml = Self::load_toml(filename)?;
        toml.into_configuration()
            .context(format!("Parsing configuration file {}", filename.display()))
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
