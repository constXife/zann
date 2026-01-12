#[cfg(feature = "postgres")]
use zann_db::{connect_postgres, migrate};

#[cfg(feature = "postgres")]
#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = connect_postgres(&db_url)
        .await
        .expect("failed to connect to database");
    migrate(&pool).await.expect("failed to run migrations");
}

#[cfg(not(feature = "postgres"))]
fn main() {
    eprintln!("zann-db migrate requires the postgres feature");
    std::process::exit(1);
}
