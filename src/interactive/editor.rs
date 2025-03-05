use anyhow::{bail, Context};
use async_trait::async_trait;
use futures::future::BoxFuture;
use inquire::{Confirm, Select};
use std::borrow::Cow;
use std::fmt::Display;

#[async_trait]
pub trait ConfigElementEditor<C: Send + Sync>: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_value<'a>(&'a self, config: &'a C) -> Cow<'a, str>;
    async fn edit(&mut self, config: C) -> anyhow::Result<C>;
}

pub type GetFunction<'a, C> = dyn Fn(&C) -> Cow<str> + Send + Sync + 'a;
pub type EditFunction<'a, C> = dyn FnMut(C) -> BoxFuture<'a, anyhow::Result<C>> + Send + Sync + 'a;
pub type ValidateFunction<'a, C> = dyn Fn(&C) -> BoxFuture<'a, anyhow::Result<bool>> + Send + Sync + 'a;

pub struct ClosureEditor<'a, C> {
    name: String,
    get: &'a GetFunction<'a, C>,
    edit: Box<EditFunction<'a, C>>,
}

impl<'a, C: Send + Sync> ClosureEditor<'a, C> {
    pub fn new<G, E>(name: impl Into<String>, get: &'a G, edit: E) -> Self
    where
        G: Fn(&C) -> Cow<str> + Send + Sync,
        E: FnMut(C) -> BoxFuture<'a, anyhow::Result<C>> + Send + Sync + 'a,
    {
        Self {
            name: name.into(),
            get,
            edit: Box::new(edit),
        }
    }
}

#[async_trait]
impl<C: Send + Sync> ConfigElementEditor<C> for ClosureEditor<'_, C> {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_value<'a>(&'a self, config: &'a C) -> Cow<'a, str> {
        (self.get)(config)
    }

    async fn edit(&mut self, config: C) -> anyhow::Result<C> {
        (self.edit)(config).await
    }
}

enum ConfigSelectable<'a, C> {
    Config {
        editor: &'a dyn ConfigElementEditor<C>,
        config: &'a C,
        index: usize,
    },
    Confirm,
    Abort,
}

impl<C: Send + Sync> Display for ConfigSelectable<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSelectable::Config { editor, config, .. } => {
                write!(f, "{}: {}", editor.get_name(), editor.get_value(config))
            }
            ConfigSelectable::Confirm => {
                write!(f, "Confirm")
            }
            ConfigSelectable::Abort => {
                write!(f, "Abort")
            }
        }
    }
}

pub struct InteractiveConfigEditor<'a, C: Send + Sync, E: ConfigElementEditor<C>> {
    message: String,
    config: C,
    editors: Vec<E>,
    validate: Box<ValidateFunction<'a, C>>,
}

impl<'a, C: Send + Sync, E: ConfigElementEditor<C>> InteractiveConfigEditor<'a, C, E> {
    pub fn new<S: Into<String>, I: Iterator<Item = E>, V>(
        prompt_message: S,
        config: C,
        editors: I,
        validation: V,
    ) -> Self
    where
        V: Fn(&C) -> BoxFuture<'a, anyhow::Result<bool>> + Send + Sync + 'a,
    {
        Self {
            message: prompt_message.into(),
            config,
            editors: editors.collect(),
            validate: Box::new(validation),
        }
    }

    pub async fn edit_config(mut self) -> anyhow::Result<C> {
        loop {
            loop {
                let mut selectables: Vec<_> = self
                    .editors
                    .iter()
                    .enumerate()
                    .map(|(index, e)| ConfigSelectable::Config {
                        editor: e,
                        config: &self.config,
                        index,
                    })
                    .collect();
                selectables.push(ConfigSelectable::Confirm);
                selectables.push(ConfigSelectable::Abort);

                let selection = match Select::new(&self.message, selectables)
                    .with_page_size(10)
                    .prompt_skippable()
                    .context("Editor aborted")?
                {
                    None => {
                        let confirm = Confirm::new("Confirm settings?")
                            .with_default(false)
                            .prompt()
                            .context("Editor aborted")?;
                        if confirm {
                            break;
                        }
                        continue;
                    }
                    Some(selection) => selection,
                };

                let selection_index = match selection {
                    ConfigSelectable::Config { index, .. } => index,
                    ConfigSelectable::Confirm => {
                        break;
                    }
                    ConfigSelectable::Abort => {
                        bail!("Editor aborted");
                    }
                };
                let editor = &mut self.editors[selection_index];
                self.config = editor.edit(self.config).await?;
            }
            let validate = (self.validate)(&self.config).await?;
            if validate {
                break;
            }
        }
        Ok(self.config)
    }
}
