use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::{Sampler, Tracer};
use opentelemetry_sdk::Resource;
use sha2::{Digest, Sha256};
use std::fs;
use tracing_subscriber::{prelude::*, EnvFilter};

use crate::app;
use crate::config::OtelConfig;
use crate::settings;
use zann_crypto::crypto::SecretKey;

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
    compute_fingerprint(
        state.config.server.fingerprint.as_deref(),
        &state.token_pepper,
        state.server_master_key.as_deref(),
    )
}

pub(crate) fn compute_fingerprint(
    configured: Option<&str>,
    token_pepper: &str,
    server_master_key: Option<&SecretKey>,
) -> String {
    if let Some(value) = configured {
        return value.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zann-fp:v1:");
    hasher.update(token_pepper.as_bytes());
    hasher.update(b":");
    if let Some(key) = server_master_key {
        hasher.update(key.as_bytes());
    }
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
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
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
    if config.insecure.unwrap_or(false) && !allow_insecure_otel() {
        return Err("otel_insecure_not_allowed".to_string());
    }

    let mut exporter = opentelemetry_otlp::new_exporter().http();
    if let Some(endpoint) = config.endpoint.as_deref() {
        exporter = exporter.with_endpoint(endpoint);
    }
    if config.insecure.unwrap_or(false) || config.ca_file.is_some() {
        let mut client_builder = reqwest::Client::builder();
        if config.insecure.unwrap_or(false) {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }
        if let Some(path) = config.ca_file.as_deref() {
            let pem = fs::read(path).map_err(|err| format!("otel_ca_read_failed: {err}"))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("otel_ca_invalid: {err}"))?;
            client_builder = client_builder.add_root_certificate(cert);
        }
        let client = client_builder
            .build()
            .map_err(|err| format!("otel_http_client_failed: {err}"))?;
        exporter = exporter.with_http_client(client);
    }
    let service_name = config
        .service_name
        .clone()
        .unwrap_or_else(|| "zann-server".to_string());
    let ratio = config.sampling_ratio.unwrap_or(1.0);
    let ratio = if (0.0..=1.0).contains(&ratio) {
        ratio
    } else {
        tracing::warn!(
            event = "otel_sampling_ratio_invalid",
            ratio,
            "sampling_ratio must be between 0 and 1"
        );
        1.0
    };
    let sampler = Sampler::TraceIdRatioBased(ratio);
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                .with_resource(Resource::new(vec![KeyValue::new(
                    "service.name",
                    service_name,
                )]))
                .with_sampler(sampler),
        )
        .install_batch(runtime::Tokio)
        .map_err(|err| format!("otel_install_failed: {err}"))?;
    global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = tracer_provider.tracer("zann-server");
    global::set_tracer_provider(tracer_provider);
    Ok(tracer)
}

fn allow_insecure_otel() -> bool {
    std::env::var("ZANN_TRACING_OTEL_ALLOW_INSECURE")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
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

#[cfg(all(feature = "jemalloc", unix))]
#[allow(dead_code)]
// Used by the bin target; the lib target does not call this directly.
fn heap_profile_dump(dir: &str) -> Result<String, String> {
    use std::ffi::CString;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn read_bool(name: &[u8]) -> Result<bool, String> {
        unsafe {
            tikv_jemalloc_ctl::raw::read::<u8>(name)
                .map(|value| value != 0)
                .map_err(|err| err.to_string())
        }
    }

    fn write_bool(name: &[u8], value: bool) -> Result<(), String> {
        let value = if value { 1u8 } else { 0u8 };
        unsafe { tikv_jemalloc_ctl::raw::write(name, value).map_err(|err| err.to_string()) }
    }

    let mut path = PathBuf::from(dir);
    std::fs::create_dir_all(&path).map_err(|err| err.to_string())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_secs();
    let run_id = std::env::var("ZANN_TEST_RUN_ID").ok();
    let run_id = run_id
        .as_deref()
        .map(|value| {
            value
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .filter(|value| !value.is_empty());
    let filename = match run_id {
        Some(run_id) => format!("heap-{run_id}-{ts}.heap"),
        None => format!("heap-{ts}.heap"),
    };
    path.push(filename);

    let c_path = CString::new(path.to_string_lossy().as_bytes()).map_err(|err| err.to_string())?;
    if read_bool(b"config.prof\0")? {
        if !read_bool(b"prof.active\0")? {
            write_bool(b"prof.active\0", true)?;
        }
        // SAFETY: jemalloc expects a valid C string pointer for prof.dump. We keep
        // the CString alive for the duration of the call.
        let result = unsafe {
            tikv_jemalloc_ctl::raw::write(b"prof.dump\0", c_path.as_ptr())
                .map_err(|err| format!("mallctl prof.dump failed: {err}"))
        };
        if let Err(primary_err) = result {
            let fallback = unsafe {
                tikv_jemalloc_ctl::raw::write(b"prof.dump\0", std::ptr::null::<i8>())
                    .map_err(|err| format!("mallctl prof.dump (fallback) failed: {err}"))
            };
            if let Err(fallback_err) = fallback {
                return Err(format!(
                    "{primary_err}; {fallback_err} (path={})",
                    path.display()
                ));
            }
        }
        if !path.is_file() {
            tracing::warn!(event = "heap_profile_missing", path = %path.display());
        }
    } else {
        return Err("jemalloc prof config is disabled".into());
    }
    Ok(path.to_string_lossy().to_string())
}

#[allow(dead_code)]
// Used by the bin target; the lib target does not call this directly.
pub(crate) fn start_heap_profiler() {
    #[cfg(all(feature = "jemalloc", unix))]
    {
        fn read_bool(name: &[u8]) -> Result<bool, String> {
            unsafe {
                tikv_jemalloc_ctl::raw::read::<u8>(name)
                    .map(|value| value != 0)
                    .map_err(|err| err.to_string())
            }
        }

        fn write_bool(name: &[u8], value: bool) -> Result<(), String> {
            let value = if value { 1u8 } else { 0u8 };
            unsafe { tikv_jemalloc_ctl::raw::write(name, value).map_err(|err| err.to_string()) }
        }

        let enabled = std::env::var("ZANN_HEAP_PROFILE")
            .map(|value| value != "0" && !value.is_empty())
            .unwrap_or(false);
        if !enabled {
            return;
        }
        let dir = std::env::var("ZANN_HEAP_PROFILE_DIR").unwrap_or_else(|_| "/data/heap".into());
        let dir_label = dir.clone();
        {
            let config_prof = read_bool(b"config.prof\0");
            let opt_prof = read_bool(b"opt.prof\0");
            let active_prof = read_bool(b"prof.active\0");
            match (config_prof, opt_prof, active_prof) {
                (Ok(config), Ok(opt), Ok(active)) => {
                    tracing::info!(
                        event = "heap_profile_prof_flags",
                        config_prof = config,
                        opt_prof = opt,
                        prof_active = active,
                        "Jemalloc profiling flags"
                    );
                    let want_active = std::env::var("ZANN_HEAP_PROFILE_ACTIVE")
                        .map(|value| value != "0" && !value.is_empty())
                        .unwrap_or(true);
                    if config && want_active && !active {
                        if let Err(err) = write_bool(b"prof.active\0", true) {
                            tracing::warn!(
                                event = "heap_profile_active_failed",
                                error = %err
                            );
                        } else {
                            tracing::info!(event = "heap_profile_active_enabled");
                        }
                    }
                }
                _ => {
                    tracing::warn!(event = "heap_profile_prof_flags_failed");
                }
            }
        }
        tokio::spawn(async move {
            let mut signal =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                {
                    Ok(signal) => signal,
                    Err(err) => {
                        tracing::warn!(
                            event = "heap_profile_signal_failed",
                            signal = "SIGUSR1",
                            error = %err
                        );
                        return;
                    }
                };
            tracing::info!(
                event = "heap_profile_signal_ready",
                signal = "SIGUSR1",
                directory = %dir_label,
                "Heap profiler signal handler ready"
            );
            loop {
                signal.recv().await;
                match heap_profile_dump(&dir) {
                    Ok(path) => {
                        tracing::info!(
                            event = "heap_profile_dumped",
                            path = %path,
                            "Heap profile dumped"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            event = "heap_profile_dump_failed",
                            error = %err
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_prefers_configured_value() {
        let smk = SecretKey::from_bytes([1u8; 32]);
        let value = compute_fingerprint(Some("fixed"), "pepper", Some(&smk));
        assert_eq!(value, "fixed");
    }

    #[test]
    fn fingerprint_changes_with_inputs() {
        let smk_a = SecretKey::from_bytes([1u8; 32]);
        let smk_b = SecretKey::from_bytes([2u8; 32]);
        let fp_a = compute_fingerprint(None, "pepper-a", Some(&smk_a));
        let fp_b = compute_fingerprint(None, "pepper-b", Some(&smk_a));
        let fp_c = compute_fingerprint(None, "pepper-a", Some(&smk_b));

        assert_ne!(fp_a, fp_b);
        assert_ne!(fp_a, fp_c);
    }
}
