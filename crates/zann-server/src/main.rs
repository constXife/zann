#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::ref_option)]
#![allow(clippy::single_match_else)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_wraps)]

use std::time::Duration;

use zann_db::migrate;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod app;
mod bootstrap;
mod cli;
mod config;
mod domains;
mod http;
mod infra;
mod runtime;
mod settings;

#[tokio::main]
async fn main() {
    let run_mode = cli::parse_args();
    if let cli::RunMode::OpenApi { out } = run_mode.clone() {
        let spec = http::openapi::build_openapi();
        let json = serde_json::to_string_pretty(&spec).expect("openapi json");
        if let Some(path) = out {
            if let Err(err) = std::fs::write(&path, json) {
                eprintln!("failed to write openapi spec: {err}");
                std::process::exit(1);
            }
        } else {
            println!("{json}");
        }
        return;
    }
    let settings = if matches!(run_mode, cli::RunMode::Migrate) {
        settings::Settings::from_env_with_options(false)
    } else {
        settings::Settings::from_env()
    };
    let settings = match settings {
        Ok(settings) => settings,
        Err(err) => {
            tracing::error!(event = "config_load_failed", error = %err);
            std::process::exit(1);
        }
    };
    let sentry_guard = bootstrap::init_sentry(&settings);
    let sentry_enabled = sentry_guard.is_some();
    let otel_guard = bootstrap::init_tracing(sentry_enabled, &settings);
    let metrics_config = settings.config.metrics.clone();
    if matches!(
        run_mode,
        cli::RunMode::Server | cli::RunMode::Init(_) | cli::RunMode::Token(_)
    ) {
        if let Err(missing) = settings::preflight(&settings) {
            tracing::error!(
                event = "preflight_failed",
                missing = ?missing,
                "Required configuration missing"
            );
            std::process::exit(1);
        }
    }
    bootstrap::log_startup(&settings, &metrics_config);
    bootstrap::init_metrics_registry(&metrics_config);
    if matches!(run_mode, cli::RunMode::Server) {
        runtime::start_heap_profiler();
    }

    let db = match bootstrap::connect_db(&settings).await {
        Ok(db) => db,
        Err(err) => {
            tracing::error!(event = "db_connect_failed", error = %err);
            return;
        }
    };
    if matches!(run_mode, cli::RunMode::Migrate) {
        if let Err(err) = migrate(&db).await {
            tracing::error!(error = %err, "migration failed");
            std::process::exit(1);
        }
        tracing::info!("migrations applied");
        return;
    }
    if let cli::RunMode::Token(token_args) = run_mode {
        if let Err(err) = cli::tokens::run(&settings, &db, &token_args).await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if let cli::RunMode::Init(init_args) = run_mode {
        if let Err(err) = cli::init::run(&settings, &db, &init_args).await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let state = bootstrap::build_state(&settings, db);
    if matches!(run_mode, cli::RunMode::Server) {
        bootstrap::wait_for_schema(&state.db, Duration::from_secs(30)).await;
    }
    bootstrap::log_fingerprint(&state);
    bootstrap::start_background_tasks(&settings, &state);
    let app = bootstrap::build_app(&metrics_config, state);
    bootstrap::serve(&settings, app).await;

    drop(otel_guard);
    drop(sentry_guard);
}
