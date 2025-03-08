use certonaut::state::Database;
use std::path::Path;

#[tokio::main(flavor = "current_thread")]
#[allow(clippy::missing_panics_doc)]
pub async fn main() -> anyhow::Result<()> {
    let mut database_file = Path::new(".").canonicalize()?;
    database_file.push("development.sqlite");
    std::fs::remove_file(&database_file)?;
    let _ = Database::open_file(&database_file).await?;
    println!(
        "Successfully created development database {}. Remember to set environment variable DATABASE_URL=development.sqlite",
        database_file.display()
    );
    println!(
        "When making changes to any SQL query or schema, run `cargo sqlx prepare` to update the offline query data (.sqlx directory)"
    );
    Ok(())
}
