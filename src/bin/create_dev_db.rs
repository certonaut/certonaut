use certonaut::state::Database;
use std::path::Path;

#[tokio::main(flavor = "current_thread")]
#[allow(clippy::missing_panics_doc)]
pub async fn main() -> anyhow::Result<()> {
    let db_file = Path::new("development.sqlite");
    std::fs::remove_file(db_file)?;
    let _ = Database::open(Path::new("."), "development.sqlite").await?;
    println!(
        "Successfully created development database {}. Remember to set environment variable DATABASE_URL=sqlite://{}",
        db_file.display(),
        db_file.display()
    );
    println!(
        "When making changes to any SQL query or schema, run `cargo sqlx prepare` to update the offline query data (.sqlx directory)"
    );
    Ok(())
}
