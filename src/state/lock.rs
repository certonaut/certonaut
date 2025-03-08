use crate::CRATE_NAME;
use fs4::tokio::AsyncFileExt;
use std::path::Path;
use tokio::fs::File;
use tracing::{error, info};

async fn renewal_lock(config_directory: &Path) -> std::io::Result<File> {
    let lock_file = config_directory.join("renew.lock");
    let lock_file = File::create(lock_file).await?;
    if lock_file.try_lock_exclusive()? {
        Ok(lock_file)
    } else {
        // TODO: Spinner animation while we wait (if interactively running)
        info!(
            "Another {CRATE_NAME} process is currently renewing certificates. Waiting for the other process to finish..."
        );
        tokio::task::spawn_blocking(move || {
            lock_file.lock_exclusive()?;
            Ok(lock_file)
        })
        .await?
    }
}

#[must_use]
#[clippy::has_significant_drop]
pub struct RenewalLock {
    lock_file: File,
}

impl RenewalLock {
    pub async fn exclusive_lock(config_directory: &Path) -> std::io::Result<Self> {
        let lock_file = renewal_lock(config_directory).await?;
        Ok(Self { lock_file })
    }
}

impl Drop for RenewalLock {
    fn drop(&mut self) {
        if let Err(e) = self.lock_file.unlock() {
            error!("Failed to release renewal lock: {e}");
        }
    }
}
