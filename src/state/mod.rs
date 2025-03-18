use crate::state::db::test_helper::TemporaryDatabase;

mod db;
mod lock;
mod migration;
pub mod types;

pub type Database = db::Database;
pub type RenewalLock = lock::RenewalLock;

pub async fn open_test_db() -> TemporaryDatabase {
    db::test_helper::open_db().await
}