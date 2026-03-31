#[cfg(feature = "postgres")]
use sqlx_core::query::query;
#[cfg(feature = "postgres")]
use sqlx_postgres::Postgres;
#[cfg(feature = "postgres")]
use url::Url;
#[cfg(feature = "postgres")]
use zann_db::connect_postgres;

#[cfg(feature = "postgres")]
#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(feature = "postgres")]
async fn run() -> Result<(), String> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let (database_name, admin_url) = derive_admin_url(&database_url)?;

    let admin_pool = connect_postgres(&admin_url)
        .await
        .map_err(|err| format!("failed to connect to admin database: {err}"))?;

    let exists = query::<Postgres>("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(&database_name)
        .fetch_optional(&admin_pool)
        .await
        .map_err(|err| format!("failed to check database existence: {err}"))?
        .is_some();

    if exists {
        eprintln!("database already exists: {database_name}");
        return Ok(());
    }

    let escaped_name = database_name.replace('"', "\"\"");
    query::<Postgres>(&format!("CREATE DATABASE \"{escaped_name}\""))
        .execute(&admin_pool)
        .await
        .map_err(|err| format!("failed to create database {database_name}: {err}"))?;

    eprintln!("database created: {database_name}");
    Ok(())
}

#[cfg(feature = "postgres")]
fn derive_admin_url(database_url: &str) -> Result<(String, String), String> {
    let mut url =
        Url::parse(database_url).map_err(|err| format!("failed to parse DATABASE_URL: {err}"))?;
    let database_name = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| "DATABASE_URL must include a database name".to_string())?
        .to_string();
    url.set_path("/postgres");
    Ok((database_name, url.to_string()))
}

#[cfg(not(feature = "postgres"))]
fn main() {
    eprintln!("zann-db create_database requires the postgres feature");
    std::process::exit(1);
}
