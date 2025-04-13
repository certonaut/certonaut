use crate::CRATE_NAME;
use sqlx::SqlitePool;
use sqlx::migrate::MigrateError;
use tracing::warn;

// This is mainly in its own module because the sqlx::migrate! macro breaks my IDE's analyzer
pub async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
    match sqlx::migrate!("db/migrations").run(pool).await {
        Ok(()) => Ok(()),
        Err(MigrateError::VersionMissing(num)) => {
            warn!(
                "{CRATE_NAME} is missing database migration {num}. This indicates a version downgrade."
            );
            warn!(
                "Consider upgrading to the latest version to avoid problems. Continuing without database migration."
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
