use opentelemetry::global;
use opentelemetry::trace::{TraceContextExt as _, Tracer as _, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::{Sampler, Tracer};
use opentelemetry_sdk::Resource;
use std::env;
use std::fs;

#[tokio::main]
async fn main() {
    let endpoint = env::var("ZANN_TRACING_OTEL_ENDPOINT")
        .or_else(|_| env::var("OTEL_EXPORTER_OTLP_ENDPOINT"))
        .unwrap_or_default();
    if endpoint.trim().is_empty() {
        eprintln!("Missing ZANN_TRACING_OTEL_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT");
        std::process::exit(1);
    }

    let service_name =
        env::var("ZANN_TRACING_OTEL_SERVICE_NAME").unwrap_or_else(|_| "otel-smoke".to_string());
    let sampling_ratio = env::var("ZANN_TRACING_OTEL_SAMPLING_RATIO")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(1.0);
    let ca_file = env::var("ZANN_TRACING_OTEL_CA_FILE").ok();
    let insecure = env::var("ZANN_TRACING_OTEL_INSECURE")
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(false);

    let tracer = match init_tracer(
        &endpoint,
        &service_name,
        sampling_ratio,
        ca_file.as_deref(),
        insecure,
    ) {
        Ok(tracer) => tracer,
        Err(err) => {
            eprintln!("Failed to init tracer: {err}");
            std::process::exit(1);
        }
    };

    tracer.in_span("otel-smoke-span", |cx| {
        let span = cx.span();
        span.set_attribute(KeyValue::new("smoke.test", true));
        span.set_attribute(KeyValue::new("smoke.service", service_name));
        span.set_attribute(KeyValue::new("smoke.endpoint", endpoint));
    });

    global::shutdown_tracer_provider();
    println!("OTLP smoke span sent");
}

fn init_tracer(
    endpoint: &str,
    service_name: &str,
    sampling_ratio: f64,
    ca_file: Option<&str>,
    insecure: bool,
) -> Result<Tracer, String> {
    let mut exporter = opentelemetry_otlp::new_exporter().http();
    exporter = exporter.with_endpoint(endpoint);

    if insecure || ca_file.is_some() {
        let mut client_builder = reqwest::Client::builder();
        if insecure {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }
        if let Some(path) = ca_file {
            let pem = fs::read(path).map_err(|err| format!("otel_ca_read_failed: {err}"))?;
            let cert =
                reqwest::Certificate::from_pem(&pem).map_err(|err| format!("otel_ca_invalid: {err}"))?;
            client_builder = client_builder.add_root_certificate(cert);
        }
        let client = client_builder
            .build()
            .map_err(|err| format!("otel_http_client_failed: {err}"))?;
        exporter = exporter.with_http_client(client);
    }

    let ratio = if (0.0..=1.0).contains(&sampling_ratio) {
        sampling_ratio
    } else {
        1.0
    };
    let sampler = Sampler::TraceIdRatioBased(ratio);
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            Resource::new(vec![KeyValue::new("service.name", service_name.to_string())]),
        ).with_sampler(sampler))
        .install_batch(runtime::Tokio)
        .map_err(|err| format!("otel_install_failed: {err}"))?;

    global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = tracer_provider.tracer("otel-smoke");
    global::set_tracer_provider(tracer_provider);
    Ok(tracer)
}
