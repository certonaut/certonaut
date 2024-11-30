use crate::config::{ConfigBackend, Configuration};
use anyhow::Error;
use std::path::Path;
use std::str::FromStr;
use toml_edit::DocumentMut;

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

    fn into_configuration(self) -> Result<Configuration, Error> {
        Ok(toml_edit::de::from_document(self.document)?)
    }

    fn edit_toml(&mut self, config: &Configuration) -> Result<(), Error> {
        // TODO: Manually ensure that comments are kept by merging. For now, ignore.
        // Manually prettify by serializing and deserializing
        let pretty_string = toml_edit::ser::to_string_pretty(&config)?;
        let document = toml_edit::DocumentMut::from_str(&pretty_string)?;
        // This doesn't prettify
        //let document = toml_edit::ser::to_document(config)?;
        self.document = document;
        Ok(())
    }
}

impl ConfigBackend for TomlConfiguration {
    fn load<P: AsRef<Path>>(file: P) -> Result<Configuration, Error> {
        let toml = Self::load_toml(file)?;
        toml.into_configuration()
    }

    fn save<P: AsRef<Path>>(config: &Configuration, file: P) -> Result<(), Error> {
        let mut toml = Self::load_toml(&file).unwrap_or(TomlConfiguration {
            document: Default::default(),
        });
        toml.edit_toml(config)?;
        toml.write_toml(file)
    }
}
