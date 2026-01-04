use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::{middleware, Router};
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use prometheus::Encoder;
use tokio::sync::Semaphore;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::app::{self, AppState};
use crate::config::MetricsConfig;
use crate::domains::access_control::policy_store;
use crate::domains::auth::core::oidc;
use crate::infra::security_profiles;
use crate::infra::{history, metrics, usage};
use crate::runtime;
use crate::settings;
use zann_db::{connect_postgres_with_max, PgPool};

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

pub fn init_sentry(settings: &settings::Settings) -> Option<sentry::ClientInitGuard> {
    let sentry_enabled = settings.config.sentry.enabled && !settings.config.sentry.dsn.is_empty();
    if !sentry_enabled {
        return None;
    }
    let environment = settings.config.sentry.environment.clone();
    let release = settings.config.sentry.release.clone();
    Some(sentry::init((
        settings.config.sentry.dsn.as_str(),
        sentry::ClientOptions {
            environment: environment.as_deref().map(|value| value.to_string().into()),
            release: release.as_deref().map(|value| value.to_string().into()),
            ..Default::default()
        },
    )))
}

#[allow(dead_code)]
pub(crate) fn init_tracing(
    sentry_enabled: bool,
    settings: &settings::Settings,
) -> Option<runtime::OtelGuard> {
    runtime::init_tracing(sentry_enabled, settings)
}

pub fn log_startup(settings: &settings::Settings, metrics_config: &MetricsConfig) {
    let metrics_profile = metrics_config.effective_profile();
    if settings.config.server.trusted_proxies.is_empty() {
        tracing::warn!(
            event = "trusted_proxies_empty",
            "Forwarded headers are ignored; client IPs rely on direct peer address"
        );
    }
    tracing::info!(
        event = "server_startup",
        addr = %settings.addr,
        auth_mode = ?settings.config.auth.mode,
        internal_auth_enabled = settings.config.auth.internal.enabled,
        oidc_enabled = settings.config.auth.oidc.enabled,
        otel_enabled = settings.config.tracing.otel.enabled,
        metrics_enabled = metrics_config.enabled,
        metrics_profile = ?metrics_profile,
        policy_file = ?settings.config.policy.file,
        server_name = ?settings.config.server.name,
        personal_vaults_enabled = settings.config.server.personal_vaults_enabled,
        "Server configuration loaded"
    );
    if metrics_config.enabled && metrics_profile != crate::config::MetricsProfile::Prod {
        tracing::warn!(
            event = "metrics_profile_non_prod",
            profile = ?metrics_profile,
            "Non-prod metrics profile enabled"
        );
    }

    if settings.config.auth.oidc.enabled {
        let oidc = &settings.config.auth.oidc;
        let audience = oidc
            .audience
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("");
        tracing::info!(
            event = "oidc_config_loaded",
            issuer = %oidc.issuer,
            client_id = %oidc.client_id,
            audience = %audience,
            jwks_url = %oidc.jwks_url.clone().unwrap_or_default(),
            jwks_file = %oidc.jwks_file.clone().unwrap_or_default(),
            groups_claim = %oidc.groups_claim.clone().unwrap_or_default(),
            admin_group = %oidc.admin_group.clone().unwrap_or_default(),
            "OIDC config loaded"
        );
    }
}

pub fn init_metrics_registry(metrics_config: &MetricsConfig) {
    metrics::set_profile(metrics_config.effective_profile());
    if !metrics_config.enabled {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let process_collector = prometheus::process_collector::ProcessCollector::for_self();
        if prometheus::default_registry()
            .register(Box::new(process_collector))
            .is_err()
        {
            tracing::warn!("failed to register process metrics");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("process metrics are only available on linux");
    }
}

pub async fn connect_db(settings: &settings::Settings) -> Result<PgPool, sqlx_core::Error> {
    connect_postgres_with_max(&settings.db_url, settings.db_pool_max).await
}

pub fn build_state(settings: &settings::Settings, db: PgPool) -> AppState {
    let usage_tracker = std::sync::Arc::new(usage::UsageTracker::new(db.clone(), 100));
    usage_tracker
        .clone()
        .start_flush_loop(Duration::from_secs(10));

    AppState {
        db,
        started_at: Instant::now(),
        password_pepper: settings.password_pepper.clone(),
        token_pepper: settings.token_pepper.clone(),
        server_master_key: settings.server_master_key.as_ref().map(|key| {
            std::sync::Arc::new(zann_core::crypto::SecretKey::from_bytes(*key.as_bytes()))
        }),
        access_token_ttl_seconds: settings.access_token_ttl_seconds,
        refresh_token_ttl_seconds: settings.refresh_token_ttl_seconds,
        argon2_semaphore: std::sync::Arc::new(Semaphore::new(4)),
        oidc_jwks_cache: oidc::OidcJwksCache::new(),
        config: settings.config.clone(),
        policy_store: policy_store::PolicyStore::new(settings.policies.clone()),
        usage_tracker,
        security_profiles: security_profiles::load_security_profiles(),
        secret_policies: settings.secret_policies.clone(),
        secret_default_policy: settings.secret_default_policy.clone(),
    }
}

pub fn log_fingerprint(state: &AppState) {
    let fingerprint = runtime::server_fingerprint(state);
    tracing::info!("SERVER FINGERPRINT: {}", fingerprint);
}

pub fn start_background_tasks(settings: &settings::Settings, state: &AppState) {
    if let Some(ttl_days) = settings.item_history_ttl_days {
        let pool = state.db.clone();
        let interval = settings.item_history_ttl_interval_seconds;
        tokio::spawn(async move {
            let interval = Duration::from_secs(interval.max(60));
            loop {
                match history::prune_item_history_ttl(&pool, ttl_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!(
                                event = "item_history_ttl_pruned",
                                deleted = count,
                                ttl_days = ttl_days
                            );
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            event = "item_history_ttl_failed",
                            error = %err,
                            ttl_days = ttl_days
                        );
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
    {
        let pool = state.db.clone();
        let interval = settings.config.rotation.cleanup_interval_seconds.max(60);
        tokio::spawn(async move {
            let interval = Duration::from_secs(interval);
            loop {
                match history::prune_rotation_candidates(&pool).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!(event = "rotation_candidates_pruned", deleted = count);
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            event = "rotation_candidates_prune_failed",
                            error = %err
                        );
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
    if settings.config.metrics.enabled {
        metrics::start_db_pool_metrics(state.db.clone(), settings.db_pool_max);
    }
}

pub fn build_app(metrics_config: &MetricsConfig, state: AppState) -> Router {
    let request_id_header = axum::http::HeaderName::from_static("x-request-id");
    let mut app = app::build_router(state)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("unknown");
                let matched = request
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .map(axum::extract::MatchedPath::as_str)
                    .unwrap_or("unmatched");
                let span = tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    path = %matched,
                    request_id = %request_id,
                    user_id = tracing::field::Empty
                );
                let parent = global::get_text_map_propagator(|prop| {
                    prop.extract(&HeaderExtractor(request.headers()))
                });
                span.set_parent(parent);
                span
            }),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(CatchPanicLayer::custom(|err| {
            tracing::error!(event = "panic_recovered", error = ?err, "handler panicked");
            match axum::response::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::empty())
            {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!(event = "panic_response_failed", error = %err);
                    axum::response::Response::new(axum::body::Body::empty())
                }
            }
        }));
    if metrics_config.enabled {
        app = app.route_layer(middleware::from_fn(metrics::http_metrics));
    }
    if metrics_config.enabled {
        let (layer, handle) = axum_prometheus::PrometheusMetricLayer::pair();
        let path = metrics_config.endpoint.clone();
        app = app.layer(layer).route(
            &path,
            axum::routing::get(move || async move {
                let mut body = String::new();
                body.push_str(&handle.render());
                let encoder = prometheus::TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();
                if encoder.encode(&metric_families, &mut buffer).is_ok() && !buffer.is_empty() {
                    body.push('\n');
                    body.push_str(&String::from_utf8_lossy(&buffer));
                }

                let content_type = encoder.format_type().to_string();
                let mut response = axum::response::Response::new(axum::body::Body::from(body));
                if let Ok(value) = axum::http::HeaderValue::from_str(&content_type) {
                    response
                        .headers_mut()
                        .insert(axum::http::header::CONTENT_TYPE, value);
                }
                response
            }),
        );
    }
    app
}

pub async fn serve(settings: &settings::Settings, app: Router) {
    let addr: SocketAddr = settings.addr;
    tracing::info!(%addr, "listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(event = "server_bind_failed", error = %err);
            return;
        }
    };
    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(runtime::shutdown_signal())
    .await
    {
        tracing::error!(event = "server_failed", error = %err);
    }
}
