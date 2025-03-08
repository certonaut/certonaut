use crate::error::IssueResult;
use crate::state::types::{Renewal, RenewalOutcome};
use anyhow::{anyhow, Context};
use sqlx::sqlite::SqliteAutoVacuum;
use sqlx::{ConnectOptions, Executor};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::log::LevelFilter;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct Database {
    pool: sqlx::SqlitePool,
}

impl crate::state::Database {
    pub async fn open<P: AsRef<Path>>(
        config_directory: P,
    ) -> anyhow::Result<crate::state::Database> {
        let mut file = config_directory
            .as_ref()
            .canonicalize()
            .context("Normalizing database directory path failed")?;
        file.push("database.sqlite");
        Self::open_file(file).await
    }

    pub async fn open_file<P: AsRef<Path>>(
        database_file: P,
    ) -> anyhow::Result<crate::state::Database> {
        let file = database_file.as_ref();
        let uri = url::Url::from_file_path(file)
            .map_err(|()| anyhow!("Failed to parse database URI {}", file.display()))?;
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(
            &uri.to_string().replacen("file", "sqlite", 1),
        )?
        .create_if_missing(true)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .busy_timeout(DATABASE_TIMEOUT)
        .optimize_on_close(true, None);

        #[cfg(debug_assertions)]
        let options = options.log_slow_statements(LevelFilter::Debug, Duration::from_millis(500));

        let pool = sqlx::SqlitePool::connect_with(options).await?;
        let db = crate::state::Database { pool };
        super::migration::migrate(&db.pool).await?;
        Ok(db)
    }

    pub async fn add_new_renewal<T>(
        &self,
        cert_id: &str,
        result: &IssueResult<T>,
    ) -> anyhow::Result<()> {
        let outcome: RenewalOutcome = result.into();
        let failure = match result {
            Ok(_) => None,
            Err(err) => Some(err.to_string()),
        };
        let timestamp = OffsetDateTime::now_utc();
        sqlx::query!(
            "INSERT INTO renewals(cert_id, outcome, failure, timestamp) VALUES ($1, $2, $3, $4)",
            cert_id,
            outcome,
            failure,
            timestamp
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_latest_renewals(
        &self,
        cert_id: &str,
        since: OffsetDateTime,
    ) -> anyhow::Result<Vec<Renewal>> {
        let renewals = sqlx::query_as!(
            Renewal,
            "SELECT * FROM renewals WHERE cert_id = $1 AND timestamp >= $2;",
            cert_id,
            since
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(renewals)
    }
}

impl Drop for crate::state::Database {
    fn drop(&mut self) {
        // FIXME: move to async drop when #![feature(async_drop))] is stable
        futures::executor::block_on(async {
            self.pool
                .execute("PRAGMA main.incremental_vacuum;")
                .await
                .ok();
        });
    }
}
