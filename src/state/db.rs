use crate::error::IssueResult;
use crate::state::types::{external, internal};
use anyhow::{Context, anyhow};
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
        base_directory: P,
        database_file_name: &str,
    ) -> anyhow::Result<crate::state::Database> {
        let mut file = base_directory
            .as_ref()
            .canonicalize()
            .context("Normalizing database directory path failed")?;
        file.push(database_file_name);
        let file_uri = url::Url::from_file_path(&file)
            .map_err(|()| anyhow!("Failed to parse database URI {}", file.display()))?;
        let url = &file_uri.to_string().replacen("file", "sqlite", 1);
        Self::open_url(url).await
    }

    async fn open_url(url: &str) -> anyhow::Result<crate::state::Database> {
        let connect_options = sqlx::sqlite::SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .busy_timeout(DATABASE_TIMEOUT)
            .optimize_on_close(true, None);
        let pool_options = sqlx::sqlite::SqlitePoolOptions::new();

        #[cfg(debug_assertions)]
        let connect_options =
            connect_options.log_slow_statements(LevelFilter::Debug, Duration::from_millis(500));

        let pool = pool_options.connect_with(connect_options).await?;
        let db = crate::state::Database { pool };
        super::migration::migrate(&db.pool).await?;
        Ok(db)
    }

    pub async fn add_new_renewal<T>(
        &self,
        cert_id: &str,
        result: &IssueResult<T>,
    ) -> anyhow::Result<()> {
        let outcome: internal::RenewalOutcome = result.into();
        let failure = match result {
            Ok(_) => None,
            Err(err) => Some(err.to_database_string()),
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
        since: &OffsetDateTime,
    ) -> anyhow::Result<Vec<external::Renewal>> {
        let renewals = sqlx::query_as!(
            internal::Renewal,
            "SELECT * FROM renewals WHERE cert_id = $1 AND timestamp >= $2 ORDER BY id;",
            cert_id,
            since
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .filter_map(|renew| Option::<external::Renewal>::from(renew))
        .collect::<Vec<_>>();
        Ok(renewals)
    }

    pub async fn close(&self) {
        self.pool.close().await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IssueError;
    use crate::state::types::external::RenewalOutcome;
    use rstest::rstest;
    use std::ops::{Deref, DerefMut, Sub};
    use std::sync::atomic::AtomicUsize;

    struct TemporaryDatabase {
        db: Database,
    }

    impl Deref for TemporaryDatabase {
        type Target = Database;

        fn deref(&self) -> &Self::Target {
            &self.db
        }
    }

    impl DerefMut for TemporaryDatabase {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.db
        }
    }

    impl TemporaryDatabase {
        pub async fn new() -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let instance = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // SQLite 3.36+ allows us to share DB connections using the memdb VFS.
            // This is preferred over the (much) older trick where a :memory: DB could be shared using
            // the (now deprecated) shared cache mode.
            // See https://sqlite.org/forum/info/6700ab1f9f6e8a00 for discussion
            let file_name = format!("sqlite:///inmem-{instance}.db?vfs=memdb");
            Self {
                db: Database::open_url(&file_name)
                    .await
                    .expect("Failed to create new in-memory database"),
            }
        }
    }

    async fn open_db() -> TemporaryDatabase {
        TemporaryDatabase::new().await
    }

    #[tokio::test]
    async fn test_open_file_database() {
        let db = Database::open(".", "certonaut_test.sqlite").await.unwrap();
        db.close().await;
        std::fs::remove_file("certonaut_test.sqlite").unwrap();
    }

    // Sanity check to verify that sqlx actually separates the in-memory databases from each other
    #[tokio::test(flavor = "current_thread")]
    async fn databases_isolated_in_test() {
        let db_1 = open_db().await;
        let db_2 = open_db().await;

        db_1.add_new_renewal("cert_1", &Ok(())).await.unwrap();
        db_2.add_new_renewal("cert_1", &Ok(())).await.unwrap();

        let renewals_1 = db_1
            .get_latest_renewals(
                "cert_1",
                &OffsetDateTime::now_utc().sub(Duration::from_secs(30)),
            )
            .await
            .unwrap();
        let renewals_2 = db_2
            .get_latest_renewals(
                "cert_1",
                &OffsetDateTime::now_utc().sub(Duration::from_secs(30)),
            )
            .await
            .unwrap();
        assert_eq!(renewals_1.len(), 1);
        assert_eq!(renewals_2.len(), 1);
    }

    #[tokio::test]
    async fn test_add_new_renewal_with_ok() {
        let db = open_db().await;
        let result = Ok(());

        db.add_new_renewal("cert_1", &result).await.unwrap();
        let renewals = db
            .get_latest_renewals(
                "cert_1",
                &OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
            )
            .await
            .unwrap();

        assert_eq!(renewals.len(), 1);
        let renewal = renewals.first().unwrap();
        assert_eq!(renewal.cert_id, "cert_1");
        assert_eq!(renewal.outcome, RenewalOutcome::Success);
        let time_delta = OffsetDateTime::now_utc() - renewal.timestamp;
        assert!(time_delta < Duration::from_secs(3));
    }

    #[tokio::test]
    #[rstest]
    #[case(IssueError::CAFailure(anyhow!("Houston, we have a problem")), RenewalOutcome::CAFailure("Error: Houston, we have a problem".into()))]
    #[case(IssueError::RateLimited(anyhow!("I’m givin’ her all she’s got, Captain!")), RenewalOutcome::RateLimit("Error: I’m givin’ her all she’s got, Captain!".into()))]
    #[case(IssueError::AuthFailure(anyhow!("I’m sorry, Dave. I’m afraid I can’t do that.")), RenewalOutcome::AuthorizationFailure("Error: I’m sorry, Dave. I’m afraid I can’t do that.".into()))]
    #[case(IssueError::ClientFailure(anyhow!("You had one job!")), RenewalOutcome::ClientFailure("Error: You had one job!".into()))]
    async fn test_add_new_renewal_with_err(
        #[case] error: IssueError,
        #[case] outcome: RenewalOutcome,
    ) {
        let db = open_db().await;
        let result: IssueResult<()> = Err(error);

        db.add_new_renewal("cert_1", &result).await.unwrap();
        let renewals = db
            .get_latest_renewals(
                "cert_1",
                &OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
            )
            .await
            .unwrap();

        assert_eq!(renewals.len(), 1);
        let renewal = renewals.first().unwrap();
        assert_eq!(renewal.cert_id, "cert_1");
        assert_eq!(renewal.outcome, outcome);
        let time_delta = OffsetDateTime::now_utc() - renewal.timestamp;
        assert!(time_delta < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_get_latest_renewals_with_multiple_renewals() {
        let db = open_db().await;
        let results = [
            Ok(()),
            Err(IssueError::AuthFailure(anyhow!("Failure 1"))),
            Err(IssueError::ClientFailure(anyhow!("Failure 2"))),
        ];
        let cert_name = "cert_1";

        db.add_new_renewal(cert_name, &results[0]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        for result in results.iter().skip(1) {
            db.add_new_renewal(cert_name, result).await.unwrap();
        }

        let latest_renewals = db
            .get_latest_renewals(
                cert_name,
                &OffsetDateTime::now_utc().sub(Duration::from_millis(999)),
            )
            .await
            .unwrap();
        assert_eq!(latest_renewals.len(), 2);
        assert_eq!(
            latest_renewals[0].outcome,
            RenewalOutcome::AuthorizationFailure("Error: Failure 1".into())
        );
        assert_eq!(
            latest_renewals[1].outcome,
            RenewalOutcome::ClientFailure("Error: Failure 2".into())
        );
    }

    #[tokio::test]
    async fn test_get_latest_renewals_with_multiple_certs() {
        let db = open_db().await;
        let result = Ok(());
        let cert_names = ["cert_1", "cert_2"];

        for cert_name in &cert_names {
            db.add_new_renewal(cert_name, &result).await.unwrap();
        }

        for cert_name in &cert_names {
            let latest_renewals = db
                .get_latest_renewals(
                    cert_name,
                    &OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
                )
                .await
                .unwrap();
            assert_eq!(latest_renewals.len(), 1);
        }
    }
}
