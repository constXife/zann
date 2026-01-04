use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
    HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::warn;
use zann_db::PgPool;

use crate::config::MetricsProfile;

const PROFILE_PROD: u8 = 0;
const PROFILE_STAGING: u8 = 1;
const PROFILE_DEBUG: u8 = 2;

static METRICS_PROFILE: AtomicU8 = AtomicU8::new(PROFILE_PROD);

pub fn set_profile(profile: MetricsProfile) {
    let value = match profile {
        MetricsProfile::Prod => PROFILE_PROD,
        MetricsProfile::Staging => PROFILE_STAGING,
        MetricsProfile::Debug => PROFILE_DEBUG,
    };
    METRICS_PROFILE.store(value, Ordering::Relaxed);
}

fn active_profile() -> MetricsProfile {
    match METRICS_PROFILE.load(Ordering::Relaxed) {
        PROFILE_STAGING => MetricsProfile::Staging,
        PROFILE_DEBUG => MetricsProfile::Debug,
        _ => MetricsProfile::Prod,
    }
}

fn counter_vec_or_fallback(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    match register_int_counter_vec!(name, help, labels) {
        Ok(metric) => metric,
        Err(err) => {
            warn!(event = "metrics_register_failed", metric = name, error = %err);
            IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|err| {
                warn!(event = "metrics_fallback_failed", metric = name, error = %err);
                IntCounterVec::new(
                    Opts::new("zann_metrics_fallback", "metrics fallback"),
                    &["name"],
                )
                .expect("fallback metric")
            })
        }
    }
}

fn gauge_vec_or_fallback(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    match register_int_gauge_vec!(name, help, labels) {
        Ok(metric) => metric,
        Err(err) => {
            warn!(event = "metrics_register_failed", metric = name, error = %err);
            IntGaugeVec::new(Opts::new(name, help), labels).unwrap_or_else(|err| {
                warn!(event = "metrics_fallback_failed", metric = name, error = %err);
                IntGaugeVec::new(
                    Opts::new("zann_metrics_fallback", "metrics fallback"),
                    &["name"],
                )
                .expect("fallback metric")
            })
        }
    }
}

fn gauge_or_fallback(name: &str, help: &str) -> IntGauge {
    match register_int_gauge!(name, help) {
        Ok(metric) => metric,
        Err(err) => {
            warn!(event = "metrics_register_failed", metric = name, error = %err);
            IntGauge::new(name, help).unwrap_or_else(|err| {
                warn!(event = "metrics_fallback_failed", metric = name, error = %err);
                IntGauge::new("zann_metrics_fallback", "metrics fallback").expect("fallback metric")
            })
        }
    }
}

fn histogram_vec_or_fallback(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Vec<f64>,
) -> HistogramVec {
    match register_histogram_vec!(name, help, labels, buckets.clone()) {
        Ok(metric) => metric,
        Err(err) => {
            warn!(event = "metrics_register_failed", metric = name, error = %err);
            let opts = HistogramOpts::new(name, help).buckets(buckets);
            HistogramVec::new(opts, labels).unwrap_or_else(|err| {
                warn!(event = "metrics_fallback_failed", metric = name, error = %err);
                HistogramVec::new(
                    HistogramOpts::new("zann_metrics_fallback", "metrics fallback"),
                    &["name"],
                )
                .expect("fallback metric")
            })
        }
    }
}

fn http_buckets() -> Vec<f64> {
    vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

fn kdf_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0,
    ]
}

static AUTH_LOGINS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_auth_logins_total",
        "Auth login attempts",
        &["result", "method"],
    )
});

static AUTH_REGISTERS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_auth_register_total",
        "Auth registration attempts",
        &["result"],
    )
});

static OIDC_JWKS_FETCH: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_oidc_jwks_fetch_total",
        "OIDC JWKS fetch attempts",
        &["result"],
    )
});

static AUTH_TOKENS_ISSUED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_auth_tokens_issued_total",
        "Auth tokens issued",
        &["type"],
    )
});

static HTTP_IN_FLIGHT: LazyLock<IntGauge> =
    LazyLock::new(|| gauge_or_fallback("zann_http_in_flight", "HTTP requests in flight"));

static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_http_requests_total",
        "HTTP requests",
        &["method", "route", "status_class"],
    )
});

static HTTP_REQUESTS_BY_STATUS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_http_requests_by_status_total",
        "HTTP requests by status",
        &["method", "route", "status"],
    )
});

static HTTP_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram_vec_or_fallback(
        "zann_http_request_duration_seconds",
        "HTTP request latency",
        &["route"],
        http_buckets(),
    )
});

static HTTP_LATENCY_BY_STATUS: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram_vec_or_fallback(
        "zann_http_request_duration_seconds_by_status",
        "HTTP request latency by status",
        &["method", "route", "status"],
        http_buckets(),
    )
});

static KDF_WAIT_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram_vec_or_fallback(
        "zann_kdf_wait_seconds",
        "Time waiting for KDF permit",
        &["operation"],
        kdf_buckets(),
    )
});

static KDF_IN_FLIGHT: LazyLock<IntGauge> =
    LazyLock::new(|| gauge_or_fallback("zann_kdf_in_flight", "KDF operations in flight"));

static FORBIDDEN_ACCESS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_forbidden_access_total",
        "Forbidden access attempts",
        &["resource"],
    )
});

static SECRETS_OPS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    counter_vec_or_fallback(
        "zann_secrets_operations_total",
        "Secrets operations",
        &["operation", "result"],
    )
});

static SECRETS_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    histogram_vec_or_fallback(
        "zann_secrets_operation_duration_seconds",
        "Secrets operation latency",
        &["operation", "result"],
        http_buckets(),
    )
});

static DB_POOL_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    gauge_vec_or_fallback(
        "zann_db_pool_connections",
        "Database pool connections",
        &["state"],
    )
});

pub fn auth_login(result: &str, method: &str) {
    AUTH_LOGINS.with_label_values(&[result, method]).inc();
}

pub fn auth_register(result: &str) {
    AUTH_REGISTERS.with_label_values(&[result]).inc();
}

pub fn oidc_jwks_fetch(result: &str) {
    OIDC_JWKS_FETCH.with_label_values(&[result]).inc();
}

pub fn auth_tokens_issued(token_type: &str) {
    AUTH_TOKENS_ISSUED.with_label_values(&[token_type]).inc();
}

pub fn forbidden_access(resource: &str) {
    let label = match active_profile() {
        MetricsProfile::Prod => "redacted",
        MetricsProfile::Staging | MetricsProfile::Debug => resource,
    };
    FORBIDDEN_ACCESS.with_label_values(&[label]).inc();
}

pub fn secrets_operation(operation: &str, result: &str, duration_seconds: f64) {
    SECRETS_OPS.with_label_values(&[operation, result]).inc();
    SECRETS_LATENCY
        .with_label_values(&[operation, result])
        .observe(duration_seconds);
}

pub async fn http_metrics(req: Request<Body>, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_string();
    HTTP_IN_FLIGHT.inc();
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    HTTP_IN_FLIGHT.dec();
    record_http_request(&method, &route, response.status().as_u16(), elapsed);
    response
}

pub fn record_http_request(method: &str, route: &str, status: u16, duration_seconds: f64) {
    let status_class = match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "unknown",
    };
    HTTP_REQUESTS
        .with_label_values(&[method, route, status_class])
        .inc();
    HTTP_LATENCY
        .with_label_values(&[route])
        .observe(duration_seconds);

    match active_profile() {
        MetricsProfile::Prod => {}
        MetricsProfile::Staging | MetricsProfile::Debug => {
            let status_label = status.to_string();
            HTTP_REQUESTS_BY_STATUS
                .with_label_values(&[method, route, &status_label])
                .inc();
            HTTP_LATENCY_BY_STATUS
                .with_label_values(&[method, route, &status_label])
                .observe(duration_seconds);
        }
    }
}

pub struct KdfPermit<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl Drop for KdfPermit<'_> {
    fn drop(&mut self) {
        KDF_IN_FLIGHT.dec();
    }
}

pub async fn acquire_kdf_permit<'a>(
    semaphore: &'a Semaphore,
    operation: &str,
) -> Result<KdfPermit<'a>, ()> {
    let start = Instant::now();
    let permit = semaphore.acquire().await.map_err(|_| ())?;
    KDF_WAIT_SECONDS
        .with_label_values(&[operation])
        .observe(start.elapsed().as_secs_f64());
    KDF_IN_FLIGHT.inc();
    Ok(KdfPermit { _permit: permit })
}

pub fn start_db_pool_metrics(pool: PgPool, max_connections: u32) {
    let idle_metric = DB_POOL_CONNECTIONS.with_label_values(&["idle"]);
    let active_metric = DB_POOL_CONNECTIONS.with_label_values(&["active"]);
    let max_metric = DB_POOL_CONNECTIONS.with_label_values(&["max"]);
    max_metric.set(i64::from(max_connections));

    tokio::spawn(async move {
        loop {
            let idle = i64::try_from(pool.num_idle()).unwrap_or(i64::MAX);
            let size = i64::from(pool.size());
            let active = (size - idle).max(0);
            idle_metric.set(idle);
            active_metric.set(active);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
