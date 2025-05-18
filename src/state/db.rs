use crate::error::IssueResult;
use crate::state::types::{external, internal};
use crate::util::truncate_to_millis;
use anyhow::{Context, anyhow};
use sqlx::Executor;
use sqlx::sqlite::SqliteAutoVacuum;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(60);
const EXPIRE_RENEWALS_AFTER: time::Duration = time::Duration::days(91);

#[derive(Debug)]
pub struct Database {
    pool: sqlx::SqlitePool,
}

impl crate::state::Database {
    pub async fn open<P: AsRef<Path>>(
        base_directory: P,
        database_file_name: &str,
    ) -> anyhow::Result<crate::state::Database> {
        let mut file = base_directory.as_ref().canonicalize().context(format!(
            "Normalizing database directory path {} failed",
            base_directory.as_ref().display()
        ))?;
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
        let connect_options = sqlx::ConnectOptions::log_slow_statements(
            connect_options,
            tracing::log::LevelFilter::Debug,
            Duration::from_millis(500),
        );

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
        let timestamp = truncate_to_millis(OffsetDateTime::now_utc());
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
    ) -> anyhow::Result<Vec<external::Renewal>> {
        let since = truncate_to_millis(since);
        let renewals = sqlx::query_as!(
            internal::Renewal,
            "SELECT * FROM renewals WHERE cert_id = $1 AND timestamp_unix >= unixepoch($2, 'subsec') ORDER BY id;",
            cert_id,
            since
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .filter_map(Option::<external::Renewal>::from)
        .collect::<Vec<_>>();
        Ok(renewals)
    }

    pub async fn get_renewal_information(
        &self,
        cert_id: &str,
    ) -> anyhow::Result<Option<external::RenewalInformation>> {
        let renewal_info = sqlx::query_as!(
            internal::RenewalInformation,
            "SELECT * FROM renewal_info WHERE cert_id = $1;",
            cert_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(std::convert::Into::into);
        Ok(renewal_info)
    }

    pub async fn set_renewal_information(
        &self,
        renewal_info: external::RenewalInformation,
    ) -> anyhow::Result<()> {
        let renewal_info: internal::RenewalInformation = renewal_info.into();
        sqlx::query!(
            "INSERT INTO renewal_info (cert_id, fetched_at, renewal_time, next_update) VALUES ($1, $2, $3, $4) \
            ON CONFLICT(cert_id) DO UPDATE \
            SET fetched_at = $2, renewal_time = $3, next_update = $4;",
            renewal_info.cert_id,
            renewal_info.fetched_at,
            renewal_info.renewal_time,
            renewal_info.next_update
        )
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub fn background_cleanup(&self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        // Pool is internally an Arc, so this is the same pool
        let pool = self.pool.clone();
        tokio::task::spawn(async move {
            let expire_after =
                truncate_to_millis(OffsetDateTime::now_utc() - EXPIRE_RENEWALS_AFTER);
            sqlx::query!(
                "DELETE FROM renewals WHERE timestamp_unix < unixepoch($1, 'subsec')",
                expire_after
            )
            .execute(&pool)
            .await?;
            sqlx::query!(
                "DELETE FROM renewal_info WHERE next_update_unix < unixepoch($1, 'subsec')",
                expire_after
            )
            .execute(&pool)
            .await?;
            pool.execute("PRAGMA main.incremental_vacuum;").await?;
            pool.execute("VACUUM main;").await?;
            Ok(())
        })
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

pub mod test_helper {
    use crate::state::db::Database;
    use std::ops::{Deref, DerefMut};
    use std::sync::atomic::AtomicUsize;

    pub struct TemporaryDatabase {
        db: Database,
    }

    impl From<TemporaryDatabase> for Database {
        fn from(value: TemporaryDatabase) -> Self {
            value.db
        }
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

    pub async fn open_db() -> TemporaryDatabase {
        TemporaryDatabase::new().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IssueError;
    use crate::state::db::test_helper::open_db;
    use crate::state::types::external::RenewalOutcome;
    use rstest::rstest;
    use std::ops::{Add, Sub};

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
                OffsetDateTime::now_utc().sub(Duration::from_secs(30)),
            )
            .await
            .unwrap();
        let renewals_2 = db_2
            .get_latest_renewals(
                "cert_1",
                OffsetDateTime::now_utc().sub(Duration::from_secs(30)),
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
                OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
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
    #[case(IssueError::CAFailure(anyhow!("Houston, we have a problem")), RenewalOutcome::CAFailure("Error: Houston, we have a problem".into()
    ))]
    #[case(IssueError::RateLimited(anyhow!("I’m givin’ her all she’s got, Captain!")), RenewalOutcome::RateLimit("Error: I’m givin’ her all she’s got, Captain!".into()
    ))]
    #[case(
        IssueError::AuthFailure(anyhow!("I’m sorry, Dave. I’m afraid I can’t do that.")),
        RenewalOutcome::AuthorizationFailure("Error: I’m sorry, Dave. I’m afraid I can’t do that.".into())
    )]
    #[case(IssueError::ClientFailure(anyhow!("You had one job!")), RenewalOutcome::ClientFailure("Error: You had one job!".into()
    ))]
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
                OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
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
        let epoch = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let db = open_db().await;
        let results = [
            Ok(()),
            Err(IssueError::AuthFailure(anyhow!("Failure 1"))),
            Err(IssueError::ClientFailure(anyhow!("Failure 2"))),
        ];
        let cert_name = "cert_1";

        db.add_new_renewal(cert_name, &results[0]).await.unwrap();
        let insert_time = db
            .get_latest_renewals(cert_name, epoch)
            .await
            .unwrap()
            .first()
            .unwrap()
            .timestamp;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // Ensure that the system time has actually moved forward... *sigh*, clock issues are fun...
            if OffsetDateTime::now_utc() - Duration::from_secs(1) >= insert_time {
                break;
            }
        }
        for result in results.iter().skip(1) {
            db.add_new_renewal(cert_name, result).await.unwrap();
        }

        let latest_renewals = db
            .get_latest_renewals(
                cert_name,
                insert_time.add(time::Duration::milliseconds(500)),
            )
            .await
            .unwrap();
        assert_eq!(
            latest_renewals.len(),
            2,
            "Unexpected num of renewals, found {latest_renewals:?}, insert_time {insert_time}"
        );
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
                    OffsetDateTime::now_utc().sub(Duration::from_secs(5)),
                )
                .await
                .unwrap();
            assert_eq!(latest_renewals.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_get_renewal_information() {
        let db = open_db().await;
        let now_truncated = truncate_to_millis(OffsetDateTime::now_utc());
        let renewal_info = external::RenewalInformation {
            cert_id: "test-cert".to_string(),
            fetched_at: now_truncated,
            renewal_time: now_truncated,
            next_update: now_truncated,
        };
        db.set_renewal_information(renewal_info.clone())
            .await
            .unwrap();

        let stored_renewal_info = db
            .get_renewal_information(&renewal_info.cert_id)
            .await
            .unwrap();

        assert_eq!(renewal_info, stored_renewal_info.unwrap());
    }

    #[tokio::test]
    async fn test_get_renewal_information_with_empty_result() {
        let db = open_db().await;

        let stored_renewal_info = db.get_renewal_information("does-not-exist").await.unwrap();

        assert_eq!(stored_renewal_info, None);
    }

    #[tokio::test]
    async fn test_get_renewal_information_with_multiple_sets() {
        let db = open_db().await;
        let now_truncated = truncate_to_millis(OffsetDateTime::now_utc());
        let renewal_info_1 = external::RenewalInformation {
            cert_id: "test-cert".to_string(),
            fetched_at: now_truncated,
            renewal_time: now_truncated,
            next_update: now_truncated,
        };
        let renewal_info_2 = external::RenewalInformation {
            cert_id: "test-cert".to_string(),
            fetched_at: now_truncated.add(time::Duration::hours(1)),
            renewal_time: now_truncated.add(time::Duration::hours(2)),
            next_update: now_truncated.add(time::Duration::hours(3)),
        };
        db.set_renewal_information(renewal_info_1).await.unwrap();
        db.set_renewal_information(renewal_info_2.clone())
            .await
            .unwrap();

        let stored_renewal_info = db
            .get_renewal_information(&renewal_info_2.cert_id)
            .await
            .unwrap();

        assert_eq!(renewal_info_2, stored_renewal_info.unwrap());
    }

    #[tokio::test]
    async fn test_background_cleanup_with_empty_db() -> anyhow::Result<()> {
        let db = open_db().await;

        db.background_cleanup().await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_background_cleanup_with_recent_entry() -> anyhow::Result<()> {
        let db = open_db().await;
        let renewal_info = external::RenewalInformation {
            cert_id: "test-cert".to_string(),
            fetched_at: OffsetDateTime::now_utc(),
            renewal_time: OffsetDateTime::now_utc(),
            next_update: OffsetDateTime::now_utc(),
        };
        db.set_renewal_information(renewal_info).await?;

        db.background_cleanup().await??;

        let renewals = db.get_renewal_information("test-cert").await?;
        assert!(renewals.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn test_background_cleanup_with_old_entry() -> anyhow::Result<()> {
        let db = open_db().await;
        let old_date = truncate_to_millis(OffsetDateTime::now_utc())
            - time::Duration::days(91).add(time::Duration::milliseconds(1));
        let renewal_info = external::RenewalInformation {
            cert_id: "test-cert".to_string(),
            fetched_at: old_date,
            renewal_time: old_date,
            next_update: old_date,
        };
        db.set_renewal_information(renewal_info).await?;

        db.background_cleanup().await??;

        let renewals = db.get_renewal_information("test-cert").await?;
        assert!(renewals.is_none());
        Ok(())
    }
}
