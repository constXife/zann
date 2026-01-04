use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::Tracer;
use opentelemetry_sdk::Resource;
use sha2::{Digest, Sha256};
use tracing_subscriber::{prelude::*, EnvFilter};

use crate::app;
use crate::config::OtelConfig;
use crate::settings;

#[allow(dead_code)]
pub(crate) struct OtelGuard {
    tracer: Tracer,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        global::shutdown_tracer_provider();
    }
}

pub(crate) fn server_fingerprint(state: &app::AppState) -> String {
    if let Some(value) = state.config.server.fingerprint.clone() {
        return value;
    }
    let mut hasher = Sha256::new();
    hasher.update(state.token_pepper.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[allow(dead_code)]
pub(crate) fn init_tracing(
    sentry_enabled: bool,
    settings: &settings::Settings,
) -> Option<OtelGuard> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "zann_server=info,tower_http=info,sqlx=warn".into());
    let format_json = std::env::var("LOG_FORMAT").unwrap_or_default() == "json";

    let sentry_layer = sentry_enabled.then(sentry_tracing::layer);

    let otel_guard = if settings.config.tracing.otel.enabled {
        match init_otel(&settings.config.tracing.otel) {
            Ok(tracer) => Some(OtelGuard { tracer }),
            Err(err) => {
                tracing::warn!(event = "otel_init_failed", error = %err);
                None
            }
        }
    } else {
        None
    };
    let otel_layer = otel_guard
        .as_ref()
        .map(|guard| tracing_opentelemetry::layer().with_tracer(guard.tracer.clone()));

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(sentry_layer)
        .with(otel_layer);
    if format_json {
        registry
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .init();
    } else {
        registry
            .with(tracing_subscriber::fmt::layer().pretty())
            .init();
    }

    if !settings.config.sentry.enabled && !settings.config.sentry.dsn.is_empty() {
        tracing::warn!("sentry dsn configured but sentry.enabled is false");
    }

    otel_guard
}

#[allow(dead_code)]
fn init_otel(config: &OtelConfig) -> Result<Tracer, String> {
    let mut exporter = opentelemetry_otlp::new_exporter().http();
    if let Some(endpoint) = config.endpoint.as_deref() {
        exporter = exporter.with_endpoint(endpoint);
    }
    let service_name = config
        .service_name
        .clone()
        .unwrap_or_else(|| "zann-server".to_string());
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            Resource::new(vec![KeyValue::new("service.name", service_name)]),
        ))
        .install_batch(runtime::Tokio)
        .map_err(|err| format!("otel_install_failed: {err}"))?;
    global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = tracer_provider.tracer("zann-server");
    global::set_tracer_provider(tracer_provider);
    Ok(tracer)
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(event = "shutdown_signal_failed", signal = "CTRL_C", error = %err);
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!(
                    event = "shutdown_signal_failed",
                    signal = "SIGTERM",
                    error = %err
                );
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!(
        event = "shutdown_signal_received",
        "Shutdown signal received"
    );
}
