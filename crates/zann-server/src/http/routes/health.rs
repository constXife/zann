use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::env;

use crate::app::AppState;

#[derive(Serialize, JsonSchema)]
pub(crate) struct HealthResponse {
    pub(crate) status: &'static str,
    pub(crate) version: &'static str,
    pub(crate) build_commit: Option<&'static str>,
    pub(crate) uptime_seconds: u64,
    pub(crate) components: HashMap<String, HealthComponent>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct HealthComponent {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let version = env!("CARGO_PKG_VERSION");
    let build_commit = option_env!("GIT_COMMIT");

    let mut components = HashMap::new();
    let is_production = is_production_env();

    let db_ok = sqlx_core::query::query::<sqlx_postgres::Postgres>("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();
    components.insert(
        "db".to_string(),
        HealthComponent {
            status: if db_ok { "ok" } else { "error" },
            details: if db_ok {
                None
            } else if is_production {
                None
            } else {
                Some("db_ping_failed".to_string())
            },
        },
    );

    let pool_idle = state.db.num_idle();
    let pool_size = state.db.size();
    components.insert(
        "db_pool".to_string(),
        HealthComponent {
            status: if pool_idle > 0 { "ok" } else { "degraded" },
            details: if is_production {
                None
            } else {
                Some(format!("size={}, idle={}", pool_size, pool_idle))
            },
        },
    );

    let kdf_permits = state.argon2_semaphore.available_permits();
    components.insert(
        "kdf".to_string(),
        HealthComponent {
            status: if kdf_permits > 0 { "ok" } else { "degraded" },
            details: if is_production {
                None
            } else {
                Some(format!("available={}", kdf_permits))
            },
        },
    );

    let oidc_status = if state.config.auth.oidc.enabled {
        match state
            .oidc_jwks_cache
            .get_jwks(&state.config.auth.oidc)
            .await
        {
            Ok(_) => HealthComponent {
                status: "ok",
                details: None,
            },
            Err(err) => HealthComponent {
                status: "degraded",
                details: if is_production { None } else { Some(err) },
            },
        }
    } else {
        HealthComponent {
            status: "disabled",
            details: None,
        }
    };
    components.insert("oidc".to_string(), oidc_status);

    let status = if !db_ok {
        "db_error"
    } else if components
        .values()
        .any(|component| component.status == "degraded")
    {
        "degraded"
    } else {
        "ok"
    };
    let http_status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(HealthResponse {
            status,
            version,
            build_commit,
            uptime_seconds,
            components,
        }),
    )
}

fn is_production_env() -> bool {
    env::var("ZANN_ENV")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "prod" | "production"
            )
        })
        .unwrap_or(false)
}
